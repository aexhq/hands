//! `SessionPreparationPort`: prepare, materialize, dematerialize, purge.

use crate::*;

#[async_trait]
impl SessionPreparationPort for AwsHand {
    async fn prepare(&self, request: PrepareSessionRequest) -> HandResult<PreparedSession> {
        if request.bundles.len() > MAX_PREPARED_BUNDLES
            || request.bindings.len() > MAX_PREPARED_BUNDLES
        {
            return Err(invalid("preparation exceeds the bundle/binding bound"));
        }
        let projection = preparation_public_projection(&request)?;
        // Reject an unenforceable physical root before reading definitions, writing durable
        // state, or fetching any one-purpose authority.
        target_spec(
            &self.plane.cfg,
            &request.resources,
            &request.network,
            RESOURCE_CLASS,
        )?;
        // Resolve the whole immutable binding projection before consuming a bundle/secret
        // authority or mutating any durable preparation row.
        let required_bundles = self.validate_prepared_bindings(&request).await?;
        let mut supplied_bundles = HashMap::with_capacity(request.bundles.len());
        for fetch in &request.bundles {
            let digest = fetch.bundle_digest.to_string();
            if !required_bundles.contains_key(&digest) {
                return Err(invalid(
                    "preparation contains a fetch for an unreferenced bundle",
                ));
            }
            if supplied_bundles.insert(digest, fetch.clone()).is_some() {
                return Err(invalid("preparation repeats a bundle fetch"));
            }
        }
        let digest = canonical_digest(&projection)
            .map_err(|_| invalid("preparation cannot be canonicalized"))?;
        let preparation_ref = format!("preparation:{}", digest.as_str());
        let root_seal = serde_json::json!({
            "network": request.network,
            "resource_class": RESOURCE_CLASS,
            "resources": request.resources,
            "root_id": request.root_id,
        });
        let root_record = DefinitionRecord::canonical(
            request.root_id.as_str(),
            DefinitionKind::RootSeal,
            "physical",
            &root_seal,
            now_ms(),
        )
        .map_err(definition_error)?;
        self.plane
            .definitions
            .install(&root_record)
            .await
            .map_err(root_seal_error)?;
        let record = DefinitionRecord::canonical(
            request.root_id.as_str(),
            DefinitionKind::Preparation,
            request.session_id.as_str(),
            &projection,
            now_ms(),
        )
        .map_err(definition_error)?;
        self.plane
            .definitions
            .install(&record)
            .await
            .map_err(definition_error)?;

        // A replay for a still-cached bundle is network-free. On cache loss, every missing bundle
        // must carry a fresh one-purpose fetch authority. Admission is performed while holding the
        // cache read guard so cache bytes and concurrent reservations form one atomic bound; the
        // guard is released before any network await.
        let (missing_fetches, _fetch_reservation, _resident_borrows) = {
            let mut cache = self.preparation_cache.write().await;
            let mut missing_fetches = Vec::new();
            let mut resident_borrows = Vec::new();
            let mut fetch_bytes = 0usize;
            for (digest, seal) in &required_bundles {
                if let Some(bytes) = cache.bundle(digest) {
                    // Keep this Arc borrowed until fetched bundles are installed. Another
                    // preparation may evict unrelated idle entries while network I/O is pending,
                    // but it cannot turn this exact preparation into a post-fetch cache miss.
                    resident_borrows.push(bytes);
                    continue;
                }
                let fetch = supplied_bundles.get(digest).ok_or_else(|| {
                    error(
                        HandErrorCode::CapabilityUnavailable,
                        false,
                        "bundle cache recovery requires a fresh preparation fetch",
                    )
                })?;
                if fetch.expires_at_ms.get() <= now_ms()
                    || fetch.max_bytes.get() as usize > brain_protocol::MAX_TOOL_BUNDLE_BYTES
                    || fetch.max_bytes.get() < seal.bytes
                {
                    return Err(invalid(
                        "bundle fetch authority is expired or exceeds the bundle bound",
                    ));
                }
                fetch_bytes = fetch_bytes
                    .checked_add(fetch.max_bytes.get() as usize)
                    .ok_or_else(|| bundle_fetch_capacity_error(self.bundle_fetch_max_bytes))?;
                missing_fetches.push(fetch.clone());
            }
            let in_flight = *self
                .bundle_fetch_reserved
                .lock()
                .map_err(|_| temporary("bundle fetch admission lock is unavailable"))?;
            let cache_limit = cache.max_bundle_bytes;
            cache.evict_idle_to_fit(
                in_flight
                    .bytes
                    .checked_add(fetch_bytes)
                    .ok_or_else(|| bundle_fetch_capacity_error(self.bundle_fetch_max_bytes))?,
                in_flight
                    .entries
                    .checked_add(missing_fetches.len())
                    .ok_or_else(|| bundle_cache_capacity_error(cache_limit))?,
                &required_bundles.keys().cloned().collect(),
            )?;
            let reservation = BundleFetchReservation::admit(
                self.bundle_fetch_reserved.clone(),
                cache.bundle_bytes,
                cache.bundles.len(),
                fetch_bytes,
                missing_fetches.len(),
                cache.max_bundle_bytes,
                self.bundle_fetch_max_bytes,
            )?;
            (missing_fetches, reservation, resident_borrows)
        };
        let fetched_results =
            futures_util::stream::iter(missing_fetches.into_iter().map(|fetch| {
                let expected_bytes = required_bundles
                    .get(fetch.bundle_digest.as_str())
                    .expect("required fetch was validated")
                    .bytes;
                async move {
                    let digest = fetch.bundle_digest.to_string();
                    let bytes = fetch_bundle(self.plane.guest.http(), &fetch).await?;
                    if bytes.len() as u64 != expected_bytes {
                        return Err(invalid(
                            "fetched bundle bytes conflict with the immutable descriptor",
                        ));
                    }
                    HandResult::Ok((digest, Arc::new(bytes)))
                }
            }))
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        let mut fetched = HashMap::with_capacity(fetched_results.len());
        for result in fetched_results {
            let (digest, bytes) = result?;
            let prior = fetched.insert(digest, bytes);
            debug_assert!(prior.is_none());
        }
        let request = cacheable_preparation(request);
        self.preparation_cache
            .write()
            .await
            .install(request, digest.to_string(), fetched)?;
        Ok(PreparedSession {
            preparation_ref: preparation_ref.parse().expect("preparation ref"),
        })
    }

    async fn materialize_default(
        &self,
        request: CreateSandboxRequest,
    ) -> HandResult<SandboxStatus> {
        if request.target.kind != TargetKind::Default || request.target.sandbox_id.is_some() {
            return Err(invalid("default sandbox target is required"));
        }
        let preparation = self.preparation(request.target.session_id.as_str()).await?;
        if preparation.request.root_id != request.target.root_id {
            return Err(binding_error(
                "default sandbox target does not belong to the prepared root",
            ));
        }
        require_exact_root_seal(&request, &preparation.request)?;
        let installed = self
            .materialize(
                target_key(&request.target)?,
                request.target.session_id.as_str(),
                &preparation.request.resources,
                &preparation.request.network,
                request.resource_class.as_str(),
                MaterializationMode::ExplicitDefault(request.generation_intent.as_str()),
            )
            .await?;
        Ok(running_status(request.target, &installed))
    }

    async fn dematerialize_default(&self, target: SandboxTarget) -> HandResult<SandboxStatus> {
        if target.kind != TargetKind::Default || target.sandbox_id.is_some() {
            return Err(invalid("default sandbox target is required"));
        }
        let installed = self.resolve_target(&target, None).await?;
        self.terminate_target(&installed, "explicit default lifecycle operation")
            .await?;
        Ok(terminated_status(
            target,
            &installed,
            "explicit default lifecycle operation",
        ))
    }

    async fn purge_tree(&self, root_id: &str) -> HandResult<()> {
        const MAX_TARGETS_PER_PURGE_ATTEMPT: usize = 25;
        let page = self
            .plane
            .registry
            .list_root(root_id, None, MAX_TARGETS_PER_PURGE_ATTEMPT)
            .await
            .map_err(materialization_error)?;
        let mut unresolved_materialization = false;
        for record in page.items {
            if let Some(installed) = record.installed() {
                self.terminate_target(&installed, "root purge").await?;
                self.plane
                    .registry
                    .purge_terminal(&record.key, &record.generation)
                    .await
                    .map_err(materialization_error)?;
                continue;
            }
            match &record.state {
                DurableTargetState::Gone { .. } | DurableTargetState::Terminated { .. } => {
                    self.plane
                        .registry
                        .purge_terminal(&record.key, &record.generation)
                        .await
                        .map_err(materialization_error)?;
                }
                DurableTargetState::Materializing { .. } => {
                    let now = now_ms();
                    let lease = record.recovery_lease().map_err(materialization_error)?;
                    if lease.lease_expires_at_ms <= now {
                        // The lease includes the provider's full possible VM lifetime plus skew.
                        // Exact delete/refund is authoritative now; one retry closes an install-CAS
                        // race before definition rows are removed.
                        self.plane
                            .registry
                            .expire_lease(&lease, now)
                            .await
                            .map_err(materialization_error)?;
                        // A concurrent install can win the conditional delete. Re-read on the
                        // bounded delete retry before purging session definitions.
                        unresolved_materialization = true;
                        continue;
                    }
                    if lease.target_expires_at_ms <= now || lease.attempt_expires_at_ms > now {
                        // Do not replay after the target's provider lifetime, and do not race the
                        // worker that currently owns the short attempt. The long fence remains
                        // charged until exact recovery or the provider lifetime plus skew ends.
                        unresolved_materialization = true;
                        continue;
                    }

                    let recovery = recovery_request(&lease, now);
                    let recovered_lease = match self
                        .plane
                        .registry
                        .acquire(&recovery)
                        .await
                        .map_err(materialization_error)?
                    {
                        hand_core::materialization::AcquireOutcome::Acquired(recovered)
                            if recovered.recovery_attempt =>
                        {
                            recovered
                        }
                        hand_core::materialization::AcquireOutcome::Acquired(fresh) => {
                            // The row disappeared between the list and acquisition. `acquire`
                            // may have installed a fresh reservation, but no provider call has
                            // happened. Remove it immediately; deletion must never materialize a
                            // new target merely to discover that the old row was already gone.
                            self.plane
                                .registry
                                .expire_lease(&fresh, now)
                                .await
                                .map_err(materialization_error)?;
                            unresolved_materialization = true;
                            continue;
                        }
                        hand_core::materialization::AcquireOutcome::Installed(installed) => {
                            self.terminate_target(&installed, "root purge").await?;
                            self.plane
                                .registry
                                .purge_terminal(&installed.key, &installed.generation)
                                .await
                                .map_err(materialization_error)?;
                            continue;
                        }
                        hand_core::materialization::AcquireOutcome::Pending { .. }
                        | hand_core::materialization::AcquireOutcome::Gone
                        | hand_core::materialization::AcquireOutcome::Terminated => {
                            unresolved_materialization = true;
                            continue;
                        }
                    };

                    let launcher =
                        GenerationLauncher::from_durable(self.plane.clone(), &recovered_lease)
                            .map_err(materialization_error)?;
                    let physical = launcher
                        .launch(&recovered_lease)
                        .await
                        .map_err(recovery_launch_error)
                        .map_err(materialization_error)?;
                    let installed = match self
                        .plane
                        .registry
                        .install(&recovered_lease, &physical, now_ms())
                        .await
                        .map_err(materialization_error)?
                    {
                        hand_core::materialization::InstallOutcome::Installed(installed) => {
                            installed
                        }
                        hand_core::materialization::InstallOutcome::ReservationLost => {
                            // Root deletion owns cleanup. If another transition won the install
                            // CAS, destroy the exact recovered physical target and retry the
                            // durable projection rather than leaking it.
                            launcher
                                .terminate_stale(&physical)
                                .await
                                .map_err(temporary)?;
                            unresolved_materialization = true;
                            continue;
                        }
                    };
                    self.terminate_target(&installed, "root purge").await?;
                    self.plane
                        .registry
                        .purge_terminal(&installed.key, &installed.generation)
                        .await
                        .map_err(materialization_error)?;
                }
                DurableTargetState::Installed { .. } => unreachable!("handled above"),
            }
        }
        let targets_remain = !self
            .plane
            .registry
            .list_root(root_id, None, 1)
            .await
            .map_err(materialization_error)?
            .items
            .is_empty();
        if unresolved_materialization || targets_remain {
            return Err(temporary(
                "sandbox tree cleanup is incomplete; bounded purge will retry",
            ));
        }
        let definitions_purged = self
            .plane
            .definitions
            .purge_root_page(root_id, MAX_TARGETS_PER_PURGE_ATTEMPT)
            .await
            .map_err(definition_error)?;
        if !definitions_purged {
            return Err(temporary(
                "sandbox definition cleanup is incomplete; bounded purge will retry",
            ));
        }
        if !self
            .preparation_cache
            .write()
            .await
            .purge_root_page(root_id, MAX_TARGETS_PER_PURGE_ATTEMPT)
        {
            return Err(temporary(
                "session preparation cleanup is incomplete; bounded purge will retry",
            ));
        }
        Ok(())
    }
}
