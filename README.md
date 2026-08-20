# Hands

The default runtime for Brain tools. Hands contains the Linux guest, curated container image, and
AWS Lambda MicroVM adapter that implement Brain's public Hand ports.

## Components

| Path | Purpose |
| --- | --- |
| `crates/hand-guest` | WebSocket guest, tool runner, bounded output, jobs, file transfer, and workspace sync |
| `crates/hand-brain-aws` | Lambda MicroVM implementation of Brain's Hand factory and adapter ports |
| `crates/hand-lambda` | Image publication, lifecycle controls, and hosted runtime checks |
| `image/` | Curated Linux tool image |
| `tools/smoke.sh` | Local container build and end-to-end protocol smoke test |

The protocol and Brain-side client come from one immutable revision of
[`aexhq/brain`](https://github.com/aexhq/brain). Change wire contracts in Brain first, then update
the pinned revision here.

## Develop

The guest is Linux-only and uses process groups, signals, and `/proc`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
tools/smoke.sh
```

`tools/smoke.sh` requires an ARM64 Linux host, Docker, and the
`aarch64-unknown-linux-gnu` Rust target. CI also builds and tests the public AMD64/ARM64 image.

See [image/README.md](image/README.md) for the container and
[hosted/README.md](hosted/README.md) for the neutral AWS composition.

Apache-2.0 licensed.
