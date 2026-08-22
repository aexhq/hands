//! `AwsHand`: the Lambda MicroVM implementation of Brain's Hand ports.

use crate::*;

/// The canonical production implementation of Brain's Hand ports.
pub struct AwsHand {
    pub(crate) plane: Arc<HandPlane>,
    pub(crate) preparation_cache: RwLock<PreparationCache>,
    pub(crate) prepared_targets: RwLock<HashMap<String, HashSet<String>>>,
    pub(crate) secret_install_locks: [Mutex<()>; SECRET_INSTALL_LOCK_SHARDS],
    pub(crate) file_effect_locks: [Mutex<()>; FILE_EFFECT_LOCK_SHARDS],
    pub(crate) secret_delivery: StdRwLock<Option<Arc<dyn SecretDeliveryPort>>>,
    pub(crate) bundle_fetch_reserved: Arc<StdMutex<BundleFetchInFlight>>,
    pub(crate) bundle_fetch_max_bytes: usize,
    pub(crate) bundle_install_permits: Semaphore,
    pub(crate) secret_install_permits: Semaphore,
}

impl AwsHand {
    pub async fn from_env() -> anyhow::Result<Arc<Self>> {
        let cfg = HandPlaneConfig::from_env()?;
        Ok(Self::with_plane(Arc::new(HandPlane::from_env(cfg).await?)))
    }

    pub fn with_plane(plane: Arc<HandPlane>) -> Arc<Self> {
        let bundle_cache_max_bytes = plane.cfg.bundle_cache_max_bytes;
        let bundle_fetch_max_bytes = plane.cfg.bundle_fetch_max_bytes;
        Arc::new(Self {
            plane,
            preparation_cache: RwLock::new(PreparationCache::with_limit(bundle_cache_max_bytes)),
            prepared_targets: RwLock::new(HashMap::new()),
            secret_install_locks: std::array::from_fn(|_| Mutex::new(())),
            file_effect_locks: std::array::from_fn(|_| Mutex::new(())),
            secret_delivery: StdRwLock::new(None),
            bundle_fetch_reserved: Arc::new(StdMutex::new(BundleFetchInFlight::default())),
            bundle_fetch_max_bytes,
            bundle_install_permits: Semaphore::new(MAX_CONCURRENT_BUNDLE_INSTALLS),
            secret_install_permits: Semaphore::new(MAX_CONCURRENT_SECRET_INSTALLS),
        })
    }

    /// Completes the deliberate Brain↔Hand composition cycle. It must be called before a session
    /// with declared secrets first materializes; replacing an installed callback is refused.
    pub fn attach_secret_delivery(&self, port: Arc<dyn SecretDeliveryPort>) -> HandResult<()> {
        let mut slot = self
            .secret_delivery
            .write()
            .map_err(|_| temporary("secret delivery lock is unavailable"))?;
        if slot.is_some() {
            return Err(invalid("secret delivery port is already attached"));
        }
        *slot = Some(port);
        Ok(())
    }

    async fn binding(&self, root_id: &str, binding_ref: &str) -> HandResult<SealedBinding> {
        self.plane
            .definitions
            .get(root_id, DefinitionKind::Binding, binding_ref)
            .await
            .map_err(definition_error)?
            .ok_or_else(|| binding_error("binding_ref is unknown"))?
            .decode()
            .map_err(definition_error)
    }

    /// Resolves the complete preparation batch before any definition write, authority fetch, or
    /// target effect. A prepared bundle authority is useful only for the exact immutable binding
    /// in this root/session; accepting an unscoped digest bag would let a malformed caller warm
    /// unrelated code into the process cache and defer a permanent mismatch until dispatch.
    pub(crate) async fn validate_prepared_bindings(
        &self,
        request: &PrepareSessionRequest,
    ) -> HandResult<HashMap<String, ValidatedPreparedBundle>> {
        let mut seen = HashSet::with_capacity(request.bindings.len());
        for prepared in &request.bindings {
            if !seen.insert(prepared.binding_ref.to_string()) {
                return Err(binding_error("preparation repeats a binding_ref"));
            }
        }

        let validations = futures_util::stream::iter(request.bindings.iter().cloned().map(
            |prepared| async move {
                let binding = self
                    .binding(request.root_id.as_str(), prepared.binding_ref.as_str())
                    .await?;
                validate_prepared_binding_projection(
                    &prepared,
                    &binding,
                    request.root_id.as_str(),
                    request.session_id.as_str(),
                )
            },
        ))
        // Preparation is a cold control operation, but validating a large fixed Tool set one
        // strongly-consistent Dynamo read at a time would add avoidable linear latency.
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;

        let mut required = HashMap::with_capacity(validations.len());
        for validation in validations {
            merge_validated_prepared_bundle(&mut required, validation?)?;
        }
        Ok(required)
    }

    pub(crate) async fn preparation(&self, session_id: &str) -> HandResult<Preparation> {
        self.preparation_cache
            .read()
            .await
            .get(session_id)
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "session must be prepared again after Hand control-process recovery",
                )
            })
    }

    pub(crate) async fn route_for_submit(
        &self,
        request: &SubmitRequest,
    ) -> HandResult<InstalledTarget> {
        let envelope = &request.envelope;
        match (&envelope.target_ref, &envelope.generation) {
            (Some(target_ref), Some(generation)) => {
                // Hot path: Brain journaled this receipt. Do not read or write DynamoDB.
                let prep = self.preparation(envelope.session_id.as_str()).await?;
                if prep.request.root_id != envelope.root_id {
                    return Err(binding_error("prepared root does not match operation root"));
                }
                validate_operation_root_seal(envelope, &prep.request)?;
                let spec = target_spec(
                    &self.plane.cfg,
                    &prep.request.resources,
                    &prep.request.network,
                    RESOURCE_CLASS,
                )?;
                // The provider JWE authenticates public ingress, while the installed target row
                // owns the generation bearer that authenticates the supervisor inside the shared
                // guest network namespace. Resolve that durable row even for an established
                // operation so a restarted Hand never invents or loses the bearer.
                let installed = self
                    .resolve_target(&default_target(envelope)?, Some(generation.as_str()))
                    .await?;
                if installed.target_ref != target_ref.as_str()
                    || installed.spec_digest != spec.digest()
                {
                    return Err(generation_error());
                }
                Ok(installed)
            }
            (None, None) => {
                let prep = self.preparation(envelope.session_id.as_str()).await?;
                if prep.request.root_id != envelope.root_id {
                    return Err(binding_error("prepared root does not match operation root"));
                }
                validate_operation_root_seal(envelope, &prep.request)?;
                self.materialize(
                    TargetKey::for_default_target(envelope.root_id.as_str())
                        .map_err(materialization_error)?,
                    envelope.session_id.as_str(),
                    &prep.request.resources,
                    &prep.request.network,
                    RESOURCE_CLASS,
                    MaterializationMode::LazyDefault,
                )
                .await
            }
            _ => Err(invalid(
                "target_ref and generation must either both be absent or both be present",
            )),
        }
    }

    pub(crate) async fn materialize(
        &self,
        key: TargetKey,
        owner_session_id: &str,
        resources: &ResourceCeiling,
        network: &NetworkCeiling,
        resource_class: &str,
        mode: MaterializationMode<'_>,
    ) -> HandResult<InstalledTarget> {
        if resource_class != RESOURCE_CLASS {
            return Err(error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "the MVP plane exposes only the microvm-1gb resource class",
            ));
        }
        let spec = target_spec(&self.plane.cfg, resources, network, resource_class)?;
        let now = now_ms();
        let reservation_id = random_identifier("reservation");
        let generation = mode
            .generation_intent()
            .map(str::to_owned)
            .unwrap_or_else(|| random_identifier("generation"));
        let attempt_id = random_identifier("attempt");
        // Build the exact provider request before the reservation transaction. This provisional
        // value is never persisted or dispatched; it supplies only the generation/deadlines used
        // to mint the immutable run payload. The completed sealed request replaces it below.
        let mut request = AcquireTarget {
            key: key.clone(),
            spec,
            reservation_id,
            generation,
            launch_request: DurableLaunchRequest::new("unsealed")
                .expect("non-empty provisional launch request"),
            attempt_id,
            attempt_duration_ms: TARGET_ATTEMPT_MS,
            generation_is_fenced: mode.generation_intent().is_some(),
            now_ms: now,
            lease_duration_ms: TARGET_LEASE_MS,
            target_lifetime_ms: TARGET_LIFETIME_MS,
            replace_after_loss: mode.replace_after_loss(),
        };
        let launcher = GenerationLauncher {
            plane: self.plane.clone(),
            key,
            owner_session_id: owner_session_id.into(),
            resources: resources.clone(),
            network: network.clone(),
            resource_class: resource_class.into(),
        };
        let preview = request.lease().map_err(materialization_error)?;
        request.launch_request = launcher.seal_launch(&preview).await?;
        TargetMaterializer::new(self.plane.registry.clone(), launcher)
            .ensure(&request)
            .await
            .map_err(materialization_error)
    }

    pub(crate) async fn install_for_operation(
        &self,
        route: &InstalledTarget,
        request: &SubmitRequest,
    ) -> HandResult<()> {
        let envelope = &request.envelope;
        let binding = self
            .binding(envelope.root_id.as_str(), envelope.binding_ref.as_str())
            .await?;
        let descriptor = binding.bundle.as_ref().ok_or_else(|| {
            error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "managed binding has no immutable bundle",
            )
        })?;
        let install_key = format!(
            "{}:{}",
            envelope.binding_ref.as_str(),
            descriptor.bundle_digest.as_str()
        );
        let installed = self
            .prepared_targets
            .read()
            .await
            .get(&route.target_ref)
            .is_some_and(|items| items.contains(&install_key));
        if !installed {
            // Brain's maximum Tool bundle is 4 MiB. Bound concurrent transient request-body
            // copies in the hosted process and buffered bodies in a 1-GiB guest when many first
            // calls arrive at once; established calls skip this cold path entirely.
            let _install_permit = self
                .bundle_install_permits
                .acquire()
                .await
                .map_err(|_| temporary("bundle installation admission is unavailable"))?;
            // Cached bundle lookup only reads (the access clock is atomic), so concurrent
            // installs are not serialized behind the write lock.
            let bundle = self
                .preparation_cache
                .read()
                .await
                .bundle(descriptor.bundle_digest.as_str())
                .ok_or_else(|| {
                    error(
                        HandErrorCode::CapabilityUnavailable,
                        false,
                        "bundle bytes are not cached; Brain must prepare the session again",
                    )
                })?;
            self.plane
                .guest
                .post_blob(
                    route,
                    &format!("/internal/bundles/{}", descriptor.bundle_digest.as_str()),
                    &InstallBundleMetadata {
                        descriptor: descriptor.clone(),
                    },
                    bundle.as_slice(),
                )
                .await?;
            self.plane
                .guest
                .post_json(
                    route,
                    "/internal/bindings",
                    &InstallBindingRequest {
                        binding_ref: envelope.binding_ref.to_string(),
                        binding: binding.clone(),
                    },
                )
                .await?;
            self.prepared_targets
                .write()
                .await
                .entry(route.target_ref.clone())
                .or_default()
                .insert(install_key);
        }
        self.install_secrets(route, envelope, &binding).await
    }

    pub(crate) async fn install_object(
        &self,
        route: &InstalledTarget,
        object: &ObjectReference,
        staged: &StagedObject,
    ) -> HandResult<()> {
        if staged.bytes != object.bytes || staged.sha256 != object.sha256.as_str() {
            return Err(invalid(
                "staged object does not match its immutable reference",
            ));
        }
        self.plane
            .guest
            .post_file(
                route,
                &format!("/internal/objects/{}", object.sha256.as_str()),
                &InstallObjectMetadata {
                    object: object.clone(),
                },
                staged.file.path(),
                staged.bytes,
            )
            .await
    }

    async fn install_secrets(
        &self,
        route: &InstalledTarget,
        envelope: &brain_protocol::hand::OperationEnvelope,
        binding: &SealedBinding,
    ) -> HandResult<()> {
        let required = binding
            .bundle
            .as_ref()
            .map(|bundle| !bundle.required_env.is_empty())
            .unwrap_or(false);
        if !required {
            return Ok(());
        }
        let installed_key = format!("secret-session:{}", envelope.session_id.as_str());
        if self
            .already_installed(&route.target_ref, &installed_key)
            .await
        {
            return Ok(());
        }

        // Secret capabilities are single-use per logical session and physical generation.
        // A fixed shard set serializes the cold path without retaining an attacker-controlled
        // number of keys; an unrelated hash collision only delays this rare preparation step.
        let secret_lock =
            secret_install_lock_index(route.target_ref.as_str(), envelope.session_id.as_str());
        let _secret_install_guard = self.secret_install_locks[secret_lock].lock().await;
        if self
            .already_installed(&route.target_ref, &installed_key)
            .await
        {
            return Ok(());
        }
        let _secret_memory_permit = self
            .secret_install_permits
            .acquire()
            .await
            .map_err(|_| temporary("secret installation admission is unavailable"))?;
        let preparation = self.preparation(envelope.session_id.as_str()).await?;
        let capability = preparation
            .request
            .secret_capability
            .clone()
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "declared Tool environment requires a fresh preparation capability",
                )
            })?;
        let env_names = capability
            .env_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>();
        let port = self
            .secret_delivery
            .read()
            .map_err(|_| temporary("secret delivery lock is unavailable"))?
            .clone()
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "secret delivery port is not attached",
                )
            })?;
        let target = default_target(envelope)?;
        let capability_ref = capability.capability_ref.clone();
        // Remove the bearer before crossing the asynchronous callback boundary. Cancellation,
        // timeout, or an uncertain response can therefore never reuse a single-use capability.
        // Brain may prepare a fresh grant; the guest install is exact-idempotent if the first
        // response was merely lost.
        self.consume_secret_capability(envelope.session_id.as_str(), capability_ref.as_str())
            .await;
        let material = port
            .redeem(SecretDeliveryRequest {
                capability_ref,
                generation_intent: route.generation.parse().map_err(|_| generation_error())?,
                hand_id: HAND_ID.parse().expect("hand id"),
                root_id: envelope.root_id.clone(),
                session_id: envelope.session_id.clone(),
                target,
            })
            .await?;
        let mut values = material.into_env();
        if let Err(refusal) = secret_material_fits(&env_names, &values) {
            zeroize_secret_values(&mut values);
            return Err(error(
                HandErrorCode::CapabilityUnavailable,
                false,
                format!(
                    "secret delivery returned material outside the declared bounded environment: {refusal}"
                ),
            ));
        }
        let mut payload = InstallSecretsRequest {
            session_id: envelope.session_id.to_string(),
            generation: route.generation.clone(),
            env_names,
            values,
        };
        self.post_secret_payload(route, &mut payload).await?;
        self.prepared_targets
            .write()
            .await
            .entry(route.target_ref.clone())
            .or_default()
            .insert(installed_key);
        Ok(())
    }

    async fn already_installed(&self, target_ref: &str, installed_key: &str) -> bool {
        self.prepared_targets
            .read()
            .await
            .get(target_ref)
            .is_some_and(|items| items.contains(installed_key))
    }

    async fn consume_secret_capability(&self, session_id: &str, capability_ref: &str) {
        let mut cache = self.preparation_cache.write().await;
        let Some(preparation) = cache.store.sessions.get_mut(session_id) else {
            return;
        };
        if preparation
            .request
            .secret_capability
            .as_ref()
            .is_some_and(|capability| capability.capability_ref.as_str() == capability_ref)
        {
            Arc::make_mut(&mut preparation.request).secret_capability = None;
        }
    }

    async fn post_secret_payload(
        &self,
        route: &InstalledTarget,
        payload: &mut InstallSecretsRequest,
    ) -> HandResult<()> {
        let result = self
            .plane
            .guest
            .post_json(route, "/internal/secrets", payload)
            .await;
        zeroize_secret_values(&mut payload.values);
        result
    }

    pub(crate) async fn resolve_target(
        &self,
        target: &SandboxTarget,
        expected_generation: Option<&str>,
    ) -> HandResult<InstalledTarget> {
        let key = target_key(target)?;
        let record = self
            .plane
            .registry
            .get(&key)
            .await
            .map_err(materialization_error)?
            .ok_or_else(|| {
                error(
                    HandErrorCode::SandboxNotMaterialized,
                    false,
                    "sandbox has never been materialized",
                )
            })?;
        let installed = match record.state {
            DurableTargetState::Installed { .. } => record.installed().expect("installed target"),
            DurableTargetState::Closed { .. } => {
                return Err(error(HandErrorCode::SandboxGone, false, "sandbox is gone"));
            }
            DurableTargetState::Materializing { .. } => {
                return Err(temporary("sandbox materialization is in progress"));
            }
        };
        if expected_generation.is_some_and(|expected| expected != installed.generation) {
            return Err(generation_error());
        }
        if now_ms() >= installed.expires_at_ms {
            self.confirm_provider_termination(&installed).await?;
            self.record_gone(&installed, "physical target hard deadline reached")
                .await?;
            return Err(error(
                HandErrorCode::SandboxGone,
                false,
                "sandbox physical generation has expired",
            ));
        }
        Ok(installed)
    }

    pub(crate) async fn resolve_operation_target(
        &self,
        operation: &OperationRef,
    ) -> HandResult<InstalledTarget> {
        let installed = self
            .resolve_target(&operation.target, Some(operation.generation.as_str()))
            .await?;
        if installed.target_ref != operation.target_ref.as_str() {
            return Err(generation_error());
        }
        Ok(installed)
    }

    pub(crate) async fn terminate_target(
        &self,
        installed: &InstalledTarget,
        reason: &str,
    ) -> HandResult<()> {
        self.confirm_provider_termination(installed).await?;
        self.plane
            .registry
            .mark_closed(installed, Disposition::Terminated, reason, now_ms())
            .await
            .map_err(materialization_error)?;
        self.forget_target(installed).await;
        Ok(())
    }

    /// Confirms that a physical target no longer consumes provider memory before any registry
    /// transition refunds its charged plane capacity. A successful/ambiguous terminate response
    /// is not enough: only `Terminated` or authoritative not-found closes the accounting fence.
    pub(crate) async fn confirm_provider_termination(
        &self,
        installed: &InstalledTarget,
    ) -> HandResult<()> {
        // Every retry reconciles provider state before another state-changing call. In
        // particular, `Terminating` is not considered absent: it may still consume account memory
        // and the registry capacity counter must remain charged until termination is confirmed.
        match self.plane.control.get(&installed.target_ref).await {
            Err(ControlError::Gone(_)) => {}
            Ok(vm) if is_terminated(&vm.state) => {}
            Ok(vm) if vm.state == aws_sdk_lambdamicrovms::types::MicrovmState::Terminating => {
                return Err(temporary("sandbox termination is still in progress"));
            }
            Ok(_) => match self.plane.control.terminate(&installed.target_ref).await {
                Ok(()) | Err(ControlError::Unknown(_)) => {
                    match self.plane.control.get(&installed.target_ref).await {
                        Err(ControlError::Gone(_)) => {}
                        Ok(vm) if is_terminated(&vm.state) => {}
                        _ => {
                            return Err(temporary(
                                "sandbox termination outcome is not yet confirmed",
                            ));
                        }
                    }
                }
                Err(ControlError::Gone(_)) => {}
                Err(error_value) => return Err(control_error(error_value)),
            },
            Err(error_value) => return Err(control_error(error_value)),
        }
        Ok(())
    }

    async fn forget_target(&self, installed: &InstalledTarget) {
        self.plane.guest.forget(&installed.target_ref).await;
        self.prepared_targets
            .write()
            .await
            .remove(&installed.target_ref);
    }

    /// A provider-confirmed loss must release this plane's charged capacity before Brain is told
    /// that a fresh default generation may be created. Otherwise the durable registry would keep
    /// routing retries to a dead VM and status would lie indefinitely.
    pub(crate) async fn record_gone(
        &self,
        installed: &InstalledTarget,
        reason: &str,
    ) -> HandResult<()> {
        self.plane
            .registry
            .mark_closed(installed, Disposition::Lost, reason, now_ms())
            .await
            .map_err(materialization_error)?;
        self.forget_target(installed).await;
        Ok(())
    }

    /// Persistent endpoint 502 means the supervisor generation cannot be re-armed, even when
    /// GetMicrovm still says RUNNING. It does not, by itself, prove that provider memory was
    /// released. Terminate and reconcile first; otherwise keep the reservation charged and ask
    /// Brain to retry recovery.
    async fn retire_endpoint_lost_target(&self, installed: &InstalledTarget) -> HandResult<()> {
        self.confirm_provider_termination(installed).await?;
        self.record_gone(
            installed,
            "guest supervisor endpoint is permanently unavailable",
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn settle_guest_result<T>(
        &self,
        installed: &InstalledTarget,
        result: HandResult<T>,
    ) -> HandResult<T> {
        match result {
            Err(error_value) if error_value.code == HandErrorCode::SandboxGone => {
                self.retire_endpoint_lost_target(installed).await?;
                Err(error_value)
            }
            result => result,
        }
    }

    pub(crate) async fn guest_rpc(
        &self,
        installed: &InstalledTarget,
        call: RequestCall,
    ) -> HandResult<ResponseReply> {
        let result = self.plane.guest.rpc(installed, call).await;
        self.settle_guest_result(installed, result).await
    }

    /// Dispatches the one RPC whose missing receipt can hide a started Tool effect. A persistent
    /// endpoint loss is deliberately *not* reconciled to a Gone target here: that durable target
    /// fence is what forces every lost-response retry back to the same physical generation. Brain
    /// records the unknown outcome, then observes/schedules the target's bounded hard-deadline
    /// cleanup before a later explicit generation may replace it.
    pub(crate) async fn guest_submit_rpc(
        &self,
        installed: &InstalledTarget,
        request: SubmitRequest,
    ) -> HandResult<ResponseReply> {
        self.plane
            .guest
            .rpc(installed, RequestCall::Submit(Box::new(request)))
            .await
            .map_err(classify_submit_delivery_error)
    }

    pub(crate) async fn reserve_file_effect(
        &self,
        installed: &InstalledTarget,
        identity: FileEffectIdentity,
    ) -> HandResult<FileEffectReservation> {
        match self
            .guest_rpc(installed, RequestCall::ReserveFileEffect(identity))
            .await?
        {
            ResponseReply::ReserveFileEffect(reservation) => Ok(reservation),
            _ => Err(wrong_reply("file reservation")),
        }
    }

    pub(crate) async fn claim_file_effect(
        &self,
        installed: &InstalledTarget,
        identity: FileEffectIdentity,
    ) -> HandResult<FileEffectReservation> {
        match self
            .guest_rpc(installed, RequestCall::ClaimFileEffect(identity))
            .await?
        {
            ResponseReply::ClaimFileEffect(reservation) => Ok(reservation),
            _ => Err(wrong_reply("file claim")),
        }
    }
}
