# hands

The default **Hand** runtime: where Brain tools run. This repository contains the guest that serves
Brain's public Brain↔Hand ABI, the generic Node tool runner, a Docker image, and the AWS Lambda
MicroVM adapter used by Aex.

| Crate / dir | What |
| --- | --- |
| `crates/hand-guest` | the guest agent: serves the ABI over one WebSocket — lanes, operations with bounded spilled output, detached jobs, files in/out over presigned URLs, workspace sync (pack + manifest) and restore |
| `crates/hand-brain-aws` | AWS Lambda MicroVM implementation of Brain's public Hand ports and the neutral hosted composition binary |
| `image/` | the Dockerfile for the sandbox image (guest binary + curated toolchain) |
| `tools/` | `smoke.sh` (build image, drive one session end to end), `dev-sync.sh` (push to a Linux box and run) |

Contracts and the Brain-side client come from an immutable revision of
[`aexhq/brain`](https://github.com/aexhq/brain); their normative semantics live there. Hands
depends on Brain and implements its interfaces. Brain never depends on this repository.

## Build and test (Linux; the guest is Linux-only — setsid, signals, /proc)

```
cargo test --workspace                              # unit + end-to-end (in-process hand + client)
cargo clippy --workspace --all-targets -- -D warnings
tools/smoke.sh                                      # build the image, run it, drive a session
hand-lambda gate --image <name> --version <v>       # slice-5 gates on a real MicroVM: no IAM
                                                    # role/creds reachable from the guest (hard
                                                    # fail) + in-region tool-call latency record
```

`.github/workflows/oci.yml` publishes the public Linux AMD64/ARM64 Hand image consumed by
standalone Brain. `.github/workflows/brain-image.yml` publishes the generic hosted composition of
the pinned Brain revision, AWS durability, and this Lambda MicroVM Hand. `.github/workflows/image.yml`
is the release path for Aex's isolated MicroVM images. It reruns the
complete Rust gate on a native ARM runner, assumes a plane-scoped OIDC publisher role, and can
publish only the matching `dev` or protected `prd` environment image. Dev and production have
separate artifact buckets, build roles, image names, and version lines; no AWS keys live in
GitHub.

The published latency and security numbers live in the brain repo's `BENCHMARKS.md`
(one record for the whole platform).

License: Apache-2.0.
