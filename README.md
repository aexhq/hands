# hands

The **hand**: where an Aex agent's tools run, isolated in a microVM (AWS Lambda MicroVM now, an own
Firecracker fleet later). This repo has the guest agent that serves the brain↔hand ABI v1 and the
image it ships in; the host-side adapters (`lambda-microvm`, `firecracker-host`) land in slice 2.

| Crate / dir | What |
| --- | --- |
| `crates/hand-guest` | the guest agent: serves the ABI over one WebSocket — lanes, operations with bounded spilled output, detached jobs, files in/out over presigned URLs, workspace sync (pack + manifest) and restore |
| `crates/hand-client` | brain-side client of the ABI (one multiplexed WebSocket per hand) + a `smoke` example |
| `image/` | the Dockerfile for the sandbox image (guest binary + curated toolchain) |
| `tools/` | `smoke.sh` (build image, drive one session end to end), `dev-sync.sh` (push to a Linux box and run) |

Contracts come from [`aexhq/aex`](https://github.com/aexhq/aex) (`aex-contracts`, pinned by tag);
semantics are in that repo's `contracts/abi/v1/README.md`.

## Build and test (Linux; the guest is Linux-only — setsid, signals, /proc)

```
cargo test --workspace                              # unit + end-to-end (in-process hand + client)
cargo clippy --workspace --all-targets -- -D warnings
tools/smoke.sh                                      # build the image, run it, drive a session
hand-lambda gate --image <name> --version <v>       # slice-5 gates on a real MicroVM: no IAM
                                                    # role/creds reachable from the guest (hard
                                                    # fail) + in-region tool-call latency record
```

`.github/workflows/image.yml` is the release path for Lambda MicroVM images. It reruns the
complete Rust gate on a native ARM runner, assumes a plane-scoped OIDC publisher role, and can
publish only the matching `dev` or protected `prd` environment image. Dev and production have
separate artifact buckets, build roles, image names, and version lines; no AWS keys live in
GitHub.

The published latency and security numbers live in the brain repo's `BENCHMARKS.md`
(one record for the whole platform).

License: Apache-2.0.
