# Hands refactor plan

Target principles: `platform/docs/code.md` (AI-agent-friendly structure, SSOT, low coupling / high
cohesion, DRY+AHA, illegal states unrepresentable, fail fast, encapsulation).

Source: full read of all six crates + image/ + scripts/ (2026-08-22). Overall verdict: the repo is
healthy — tests assert real properties, comments carry rationale, the security-boundary code
(gateway `tls.rs`/`capability.rs`, guest `file_effects.rs`/`acks.rs`, `registry.rs` transactions)
is clean. The debt is structural: four god-files, cross-cutting duplication, a handful of
fail-open/silent-error spots, and dead code.

## Settled decisions (2026-08-22, with Weilue)

- **D1 Guest split depth**: sub-struct façade. `Hand` becomes a thin façade over `TargetState` /
  `Artifacts` / `Operations` / `FileEffects` / `StdinBook`, each in its own module owning its own
  lock.
- **D2 hand-brain-aws granularity**: full ~9-module split per the table, cache split into
  `PreparationStore` + `BundleCache`.
- **D3 Secret-delivery port**: keep `attach_secret_delivery` (Brain↔Hand cycle), add a startup
  self-check that the port is attached — no builder.
- **D4 Registry trait**: split into `TargetReservations` + `TargetDirectory`.
- **D5 Shared home**: new **`hand-policy` vocabulary crate** (leaf, no deps on other hands
  crates): `identity` (Identifier/Digest), `secret` (ControlToken, DurableLaunchRequest),
  `guest_env` policy, and the 512 MiB object bound. `hand-wire` depends ONLY on hand-policy
  (drops its hand-core dependency — ControlToken was its sole import); `hand-core` depends on
  hand-policy. `page<T>` stays in hand-core.
- **D6 MemoryTargetRegistry**: behind `#[cfg(any(test, feature = "test-support"))]`; rename
  `MemoryCapacity` → `PlaneAllocation`.
- **D7 Gone/Terminated**: **full merge now, storage shape included** —
  `Closed { disposition: Lost | Terminated, reason, at_ms }` with `state="closed"` + disposition
  attribute in DynamoDB, no aliases, no dual-read. MVP has zero customers and zero data; wipe dev
  tables. (Registry item mapping is hand-written — `registry.rs:679-845` — so the change is
  mechanical.) Same zero-data context removes the persisted-CAS caution on the `TargetSpec`
  digest fix.
- **D8 Brain-first items**: add the three protocol items (typed request/reply pairing,
  `RunPayload` canary field, constructible protocol types) to the Brain rewrite backlog; Hands
  ships only the cheap in-repo guards meanwhile.
- **D9 Execution**: plan doc only this session; later sessions execute phase by phase.

Execute phases in order. Each phase is independently shippable. Verify per phase:
`cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings &&
cargo test --workspace && node scripts/test-tool-runner.mjs` (guest suite on Linux).

---

## Phase 0 — Behavior fixes (small diffs, do first, each reviewable alone)

These change behavior, so they must not be buried inside the big mechanical splits.

- [ ] **Clock fail-open**: `hand-brain-aws/src/lib.rs:3360` `now_ms()` returns 0 on pre-epoch
  clock; every expiry check (`expires_at_ms <= now_ms()`) then passes. Fail closed
  (`expect` or `HandResult`).
- [ ] **Signed sandbox id fallback**: `hand-brain-aws/src/lib.rs:3349-3354` `strip_prefix(...)
  .unwrap_or("default")` — malformed target key mints a KMS-signed capability for the default
  sandbox. Error instead; add `TargetKey::sandbox_id()` to hand-core (grammar owner).
- [ ] **Non-canonical spec digest**: `hand-core/src/materialization.rs:231-238` hashes
  `serde_json::to_vec` (declaration-order) — field order is silently load-bearing for the CAS
  digest. Use `serde_jcs` (already a workspace dep); add a pinned-digest test. No compat concern
  (zero data, D7 context).
- [ ] **Lease serde hazard**: `hand-core/src/materialization.rs:255-260` `recovery_attempt` is
  `#[serde(skip)]` defaulting to the unsafe value; nothing serializes leases. Drop the
  Serialize/Deserialize derives; consider `enum LaunchProvenance { FirstDispatch, Recovery }`.
- [ ] **Panicking task leaves op Running forever**: `hand-guest/src/hand.rs:745-766, 1254-1275`
  spawn discards JoinHandle, `finish()` is sole terminal writer, and `finish` contains `.expect`s.
  Add a drop-guard that records an Interrupted terminal + `tracing::error!`; log the semaphore
  `Err(_) => return` branch.
- [ ] **Silent terminal drop**: `hand-guest/src/hand.rs:1583-1585` missing metadata discards a
  completed result with no log. Add `tracing::warn!`.
- [ ] **Oversize response closes socket silently**: `hand-guest/src/server.rs:232-260` encode
  failure / over-bound frame → bare `break`; undecodable frame → bare `continue`. Emit an error
  frame (ResourceExhausted) and keep the connection; warn-log the undecodable branch.
- [ ] **Gateway env fail-open on non-UTF-8**: `hand-egress-gateway/src/config.rs:82,177,187`
  `NotUnicode` is treated as unset — an invalid deny list silently disappears. Use `var_os` /
  match `NotUnicode` → `ConfigError::Invalid`.
- [ ] **tool-runner validates ceiling after execution + can emit no frame**:
  `image/tool-runner.mjs:19-23,49,98-104` — validate the parsed request (incl.
  `max_output_bytes`) immediately after parse in its own try (distinct exit code); pass
  `maxOutputBytes` into `writeResult` instead of reading module state.
- [ ] **Release gate aborts on transient blips**: `hand-lambda/src/canary.rs:1183-1216`
  `assert_persistent_502` propagates `Retryable|Throttled|transport` errors mid-poll while every
  neighbor retries them. Treat as "keep polling"; fail only on deadline.
- [ ] **Guest reply mismatch retried forever**: 16 sites in `hand-brain-aws` (`lib.rs:1441-2287`)
  classify wrong-variant replies as `temporary` (retryable). Reclassify as non-retryable contract
  error. (Full typed-pairing fix is Phase 4 / Brain-side.)
- [ ] **HTTP 409 for every error**: `hand-guest/src/server.rs:560-573` — add
  `status_for(HandErrorCode)` in `errors.rs` (400/404/409/413/503).

## Phase 1 — Deletions (zero-risk, shrink before splitting)

- [ ] **Delete `hand-core/src/target.rs` entirely** (571 lines): a complete second target state
  machine referenced only by its own tests, with vocabulary conflicting with
  `materialization.rs` (`TargetState` vs `DurableTargetState`, `"default"` vs `"target:default"`).
  If `Suspended`/`Terminating` are planned, fold just those into `DurableTargetState` instead.
  First salvage its generic `page<T: PageIdentity>` helper (see Phase 2).
- [ ] Dead launch paths: `hand-lambda/src/control.rs:348-364` `Control::run` and
  `launch.rs:64-80` `launch::launch` have zero callers; `canary.rs:1151-1181` open-codes a third
  copy — keep only `launch_exact` + a thin retry wrapper.
- [ ] `hand-lambda/src/image.rs:629-659` `rebuild_due`: documented as *the* base-image expiry
  safeguard, wired to nothing. Wire it into publish/CI or delete it (and fix `image.rs:9-12` docs).
- [ ] Unused deps: gateway `hex`, `sha2`, `tempfile`; hand-wire `serde_json`; hand-core dup
  dev-dep `serde_json`; hand-brain-aws `tracing-subscriber` (keep `tracing` — Phase 4 uses it).
- [ ] Guest dead code: `config.rs` `binding_dir` field (+`create_dir_all`, +hardcoded test copy);
  no-op `reserve_file_effect_inner`/`claim_file_effect_inner` passthroughs (`hand.rs:958-959`);
  duplicated `truncate_utf8` in `process.rs:942-951` (keep `errors.rs` copy, make `pub(crate)`).
- [ ] hand-lambda dead layer: `ProvideErrorMetadataExt` (`image.rs:709-711`), `detail()`
  (`image.rs:696-707`, lossy re-impl of `control.rs::sdk_error`).
- [ ] Stale docs: `hand-lambda/src/lib.rs:14-19`, `launch.rs:95`, `Cargo.toml:4` describe
  keepalive/probe/JWE features that don't exist there; `launch.rs:52` references
  `hand_guest::hooks::RunPayload` (actually `hand_wire`). Reword the five hand-core comments that
  say "MicroVM/AWS" to "provider/physical target" (crate is otherwise provider-clean).

## Phase 2 — Single source of truth (create shared homes before the splits import them)

**In-repo, Rust:**
- [ ] **New `hand-policy` crate (D5)** — leaf vocabulary crate, all four items in one move:
  - `identity`: `Identifier` + `Digest` newtypes with parse-only construction. Kills 4 copies of
    the grammar (`materialization.rs:1090-1129`, `operation.rs:237-261`, `target.rs:526-539`
    (being deleted), `hand-brain-aws/definitions.rs:310-337`) and enables the guest
    stringly-target fix (Phase 4). Each error enum gets `#[from] IdentityError`.
  - `secret`: `ControlToken` + `DurableLaunchRequest` move here from `materialization`; factor
    the shared redaction/zeroize boilerplate. While there: constant-time or documented
    `PartialEq` on `ControlToken`.
  - `guest_env`: the sandbox policy currently in hand-wire (`environment_name_is_valid`,
    `reserved_tool_environment`, `secret_material_fits` — the last returns
    `Result<(), SecretMaterialError>` instead of bool).
  - `MAX_OBJECT_BYTES`: today defined 3× (`hand-core/files.rs:19`, `hand-wire/lib.rs:31`,
    `hand-brain-aws/lib.rs:92`); one const here, others deleted.
  - Dependency edges after: `hand-wire → hand-policy` only (hand-core dep dropped);
    `hand-core → hand-policy`.
- [ ] **`hand_core::page`**: promote `Page<T>`/`PageIdentity` from target.rs before deleting it;
  use in `TargetPage`, `LiveFilePage`; one `MAX_PAGE` const (today `100` appears as literal 4×).
- [ ] `control_error` exists twice and diverged (`hand-brain-aws/lib.rs:3461` vs
  `client.rs:513` — Capacity arm differs). Single `errors` module; also move `error`/`temporary`
  constructors out of `client.rs` (dependency direction is inverted).
- [ ] DynamoDB helpers `s`/`n`/`conditional_failure`/`storage_error` duplicated between
  `registry.rs:974-995` and `definitions.rs:339-368` → small `dynamo` module generic over error.
- [ ] One `shard_index` helper for the two divergent 64-shard derivations
  (`hand-brain-aws/lib.rs:685-691` vs `2341-2345`).
- [ ] One AWS `SdkConfig` per process: `hand-lambda` bin loads two configs
  (`bin/hand-lambda.rs:222-226` + `Control::from_env`); adopt hand-brain-aws's pattern
  (`lib.rs:224-255`); drop the redundant `region` param from `image_command`; share the
  no-redirect **no_proxy** HTTP client builder (canary currently honors ambient proxies that
  production refuses). Migrate deprecated `aws_config::from_env()` → `defaults(BehaviorVersion)`
  at all 3 sites.

**Cross-language pins (extend the working `image.rs` conformance-test technique):**
- [ ] Port 8080 / uid 1000/1001 / `/usr/local/lib/hand/*` / fd 3 / 4096 headroom are hardcoded
  across C, shell, Dockerfile, Rust, JS, CI (full inventory in the assessment). Make
  `image.rs` tests assert `format!`-derived values from `AGENT_PORT`/uid consts against
  `include_str!`-ed `control-listener.c`, and replace the literal `8080`s in the tests
  themselves. Comment the `e0` capability mask in `scripts/test-control-listener-fd.sh:8`
  (= CAP_KILL|CAP_SETGID|CAP_SETUID).
- [ ] `image/hand-boot.sh` duplicates `image.rs::boot_script()` with zero coverage — loop the
  existing assertion list over both (`include_str!`), same pattern as the two-Dockerfile test.
- [ ] Tool IPC contract specified 3× (`tool-runner.mjs`, `process.rs:218-233,559-580`,
  `scripts/test-tool-runner.mjs`) — add Rust assertions pinning `+ 4096`, `writeSync(3`,
  `writeUInt32BE` against the Rust constants via `include_str!`.
- [ ] Pinned Brain revision written 6× — make `scripts/pinned-brain-revision.sh` emit
  `$GITHUB_OUTPUT` and use `${{ steps.*.outputs.revision }}` in both workflows; delete the four
  workflow literals.

**Explicitly do NOT unify:** gateway's own 8080/8081 (`hand-egress-gateway/config.rs:47-51`,
`gateway/Dockerfile:11`) — different service, coincidental numbers.

## Phase 3 — Split the god files (mechanical; land after Phase 2 so imports point at shared homes)

- [ ] **`hand-brain-aws/src/lib.rs` (4,382 → ~9 modules)**. Zero-coupling extractions first:
  `transfer.rs` (2938-3195), `launch.rs` (2347-2624), `validate.rs` (2626-2833), `status.rs`
  (3197-3365), `config.rs` (107-211), `errors.rs` (3367-3485 + capacity builders). Then
  `cache/` — split `PreparationCache` into `PreparationStore` + `BundleCache` (two unrelated LRUs
  with two clock disciplines today; the `&mut` bundle lookup forces a write lock on the hot path
  `lib.rs:1041-1044`). Then `ports/{execution,preparation,files,control}.rs`. Decompose while
  moving: `purge_tree` (1766-1936, 170 lines) → `purge_one_target` + `recover_materializing`;
  `prepare` (1559-1723) → validate/persist/admit-fetch/install; `transfer` → import/export fns;
  `install_secrets` dedupe the twice-written `installed_key` check. Tests move with modules.
  Shrink the public surface: `client`/`definitions`/`registry` → `pub(crate)`; `HandPlane`
  fields private (today `plane.registry.mark_gone(...)` can desync capacity accounting).
- [ ] **`hand-guest/src/hand.rs` (2,748 → façade + sub-modules)**. `Hand` holds 7 independent
  mutable state domains in one impl. Split per the seam map: `target.rs`, `install.rs`,
  `operations.rs`, `files.rs`, `stdin.rs`, `fence.rs`, `receipts.rs`; move the eight
  `*_error` mappers into existing `errors.rs`; each sub-struct owns its own lock. Extract
  `admit_and_spawn(...)` — `submit` (705-776) and `execute_sandbox` (1206-1283) are ~90
  near-identical lines. Fold the mid-file `use` at `hand.rs:1915` / `process.rs:519` into headers.
- [ ] **`hand-core/src/materialization.rs` (1,829 → `materialization/` dir)**:
  `spec.rs`, `record.rs`, `port.rs`, `materializer.rs`, `memory.rs` — and gate
  `MemoryTargetRegistry` (290 public lines, zero external users) behind
  `#[cfg(any(test, feature = "test-support"))]`; rename `MemoryCapacity` → `PlaneAllocation`.
  Add a curated `lib.rs` facade (`pub use`) — today everything in every module is public.
- [ ] **`hand-lambda/src/canary.rs` (1,471)**: three copy-pasted canary programs. Extract a
  `CanaryRun` builder + `with_canary_target(control, payload, |target| ...)` scope fn owning
  launch/cleanup/result-merge (the 4-arm `match (result, cleanup)` is verbatim 3×), and
  `execute_and_observe`. Move the ~300 lines of embedded Node.js into
  `canary/{restricted,public}-network.mjs` via `include_str!` (shared `probe` helper as a third
  file). Use `terminal_diagnostic` at `canary.rs:546` instead of the weaker inline copy.
- [ ] **`hand-egress-gateway/src/proxy.rs::handle_http`** (134-226): give `ProxyError` one
  `http_response()` mapping; split into `authenticate` + `establish`; one wrapper writes the
  response for any bubbled error (today 7 hand-repeated arms, and 3 paths return no response at
  all — incl. `handle_health` 404 returning `Ok`).
- [ ] **`image.rs::publish`**: split into `upload_context` / `resume_existing_publication` /
  `register(Registration::{Create|Update}, spec)` — the 35-line create/update builders are
  duplicated verbatim (508-538 vs 539-575); merge `publish_client_token` +
  `publish_request_fingerprint` (same 25-line hash twice, drift silently breaks idempotent
  resume).
- [ ] **`process.rs` dedupe**: one `run_execution` wrapper (execute_bundle/execute_shell are
  identical), one `Teardown::abort_all` (4 copies), one generic `settle` (3 copies).
- [ ] **`scripts/test-guest-deadline.mjs`**: one `sealed(value)` digest helper (5 copies), one
  `TARGET` const, one `installFixture` (35-line block ×2). ~120 lines removed.

## Phase 4 — Type-level hardening (illegal states unrepresentable; some need Brain first)

**In-repo:**
- [ ] Guest `Config`: replace `Option<tool_boundary_library>` + `Option<tool_identity>` with
  `enum Sandboxing { Enforced { identity, boundary_library }, Unenforced }` — today the mixed
  states skip `validate()` entirely (`config.rs:110-132`).
- [ ] Guest `ArmedTarget`/`TargetSnapshot`: store `Identifier`/`Digest` (from Phase 2) instead of
  `String` — deletes ~12 downstream `.parse().map_err(...)` "impossible" branches; `arm()` parses
  once.
- [ ] hand-core: private fields + `#[serde(try_from)]` on `TargetKey`/`TargetSpec`/
  `DurableTargetRecord` so deserialization *is* validation (today `validate()` is opt-in and
  never re-checks spec contents); name the 7 inline magic bounds next to the existing consts;
  rename `TargetKey::default(root_id)` → `for_default_target` (shadows `Default`).
- [ ] Registry trait split: `TargetReservations { acquire, install, expire_lease }` (all
  `TargetMaterializer` uses) vs `TargetDirectory { get, list_root, mark_gone, mark_terminated }`;
  drop the dead `now_ms` param on `expire_lease`; document (or extract) the unwritten
  `materialized_mib` charge/refund invariant both registries must uphold.
- [ ] hand-brain-aws error handling: 63 `map_err(|_| ...)` sites drop the cause and the crate
  never logs — add `temporary_from(op, e)` helper that `tracing::warn!`s + returns sanitized
  error; stop forwarding raw AWS text through the port (`storage_error` strings reach
  `HandError.message`); replace the two `_ =>` wildcards over closed local enums with exhaustive
  matches; one `with_endpoint_retry` helper in `client.rs` (retry ladder is triplicated, 4
  `unreachable!`s).
- [ ] `image.rs` stops bypassing `Control`'s error taxonomy via `control.sdk()` — image-plane
  calls behind typed methods; `wait_for_build` retries `Retryable` instead of aborting a
  30-minute publish on one 5xx; make `Control::sdk()` private. Move ELF validation and the
  `Status` version query from `bin/hand-lambda.rs` into `image.rs`; `num_args = 2` for
  `customer_hand_hosts`; pick one enforcer for the confirmation flags.
- [ ] Canary type safety: struct literals instead of `serde_json::from_value(json!({...}))`
  (10 sites — a protocol field rename currently becomes a runtime failure inside a destructive
  release gate); take `ConnectorCatalog` instead of loose refs + separately-passed class;
  `enum RestrictedClass { None, Allowlist }` deletes 4 unreachable arms; `CustomerHandHost`
  parsed once at the CLI boundary with region-derived suffix (today hardcodes us-east-1 and
  validates twice). Same JSON-round-trip fix at `hand-brain-aws/lib.rs:2151-2156`.
- [ ] hand-brain-aws smaller typed fixes: `prepared_targets` string-prefix keys →
  `enum InstalledArtifact`; `Route { Established, Lazy }` normalized at the boundary; one
  `provider_absent` / `ProviderLiveness` helper (4 sites classify provider state); one
  `capacity_error(scope, CapacityLimit)` (4 near-identical builders); `max_bundles` injected
  like its sibling limits; `preparation_for_root(session, root)` (4 copies, 3 message strings);
  secret-delivery port: keep `attach_secret_delivery`, add a startup self-check that it is
  attached (D3 — no builder);
  include the throttle `message` in `control.rs:291-301` debug log; distinct `MicrovmSummary`
  for `list()` (endpoint `None` is ambiguous today).
- [ ] hand-wire policy relocation: covered by the `hand-policy` crate in Phase 2 (D5).
- [ ] **Gone/Terminated → `Closed { disposition }` (D7 — promoted from deferred)**: merge in
  hand-core, one `mark_closed` on the trait/impls, storage writes `state="closed"` +
  `disposition` + `at_ms` — no aliases, no dual-read, wipe dev tables. Registry mapping is
  hand-written (`registry.rs:679-845`) so the change is mechanical; when implementing, confirm
  nothing else serde-persists `DurableTargetRecord`.
- [ ] Gateway small: re-export `MAX_DESTINATIONS`/`MAX_GENERATION_LIFETIME_MS` (minters can't see
  the limits they must respect); name `MAX_PORTS_PER_DESTINATION = 32`; fix the `128` literal in
  the error message that can drift from `MAX_DESTINATIONS`.
- [ ] `#![forbid(unsafe_code)]` in hand-core (contains none).

**Requires `aexhq/brain` first (per AGENTS.md — protocol changes start there). D8: file these
three on the Brain rewrite backlog now; Hands ships only the in-repo guards until the pin bumps.
A fourth for the same backlog: constructible protocol types (real struct literals / constructors)
so the canaries and `hand-brain-aws/lib.rs:2151` stop building requests via JSON round-trips.**
- [ ] Typed request/reply pairing for `RequestCall`/`ResponseReply` (16 mirrored variants;
  mismatches deserialize cleanly today). Minimum in-repo guard: `method()` discriminant check at
  every ingress. Do NOT collapse the two enums — that duplication is deliberate.
- [ ] `RunPayload.canary_exit_after_operation_id` — test-only affordance in the production seal
  type, enforced only by comment. Cargo feature or separate non-production-constructible struct.
- [ ] (Hands-internal, not Brain — listed here only for proximity to the fingerprint work:)
  `PUBLISH_REQUEST_TOKEN_SCHEMA` manual-bump contract (`image.rs:280`) — fold the fingerprint
  into one derived definition so the schema marker can't drift from the fields.

**Deferred / decide-later:**
- [ ] `files.rs` pagination re-walks the whole tree per page and `grep`'s budget can fail on
  page 2 — real, but fix is algorithmic (seed traversal from cursor), schedule when file search
  perf matters.

## Out of scope — leave alone (verified clean)

`tls.rs`, `capability.rs` (dup lifetime check is documented defense-in-depth), `file_effects.rs`,
`acks.rs`, `resources.rs`, `connector.rs`, `operation.rs` core, `definitions.rs` structure,
`registry.rs` transactions, byte-at-a-time header read in `proxy.rs` (deliberate — buffering
would corrupt the raw ClientHello capture), `image.rs` determinism tests, `control.rs` token
bucket/classify. Comments repo-wide are rationale-dense and current — don't add doc churn.
