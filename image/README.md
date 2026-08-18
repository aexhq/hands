# The hand image

`Dockerfile` builds the sandbox the agent's tools run inside: the `hand-guest` binary plus a
curated toolchain (git, Python, Node, ripgrep, build-essential, common archivers). ARM64.

The binary is built statically against musl so the image is a thin runtime layer that rebuilds
in seconds when only the code changes:

```
# on an aarch64 Linux host with the musl target and musl-tools installed
cargo build -p hand-guest --release --target aarch64-unknown-linux-musl
docker build -f image/Dockerfile \
  --build-arg BIN=target/aarch64-unknown-linux-musl/release/hand-guest \
  -t aex-hand:dev .
```

Installer output is redirected into `/workspace/.aex/**` (CARGO_HOME, GOPATH, npm prefix, pip/uv
caches, pipx) so a `pip install` or `npm i -g` survives workspace sync; system-wide installs are
ephemeral and the agent is told so.

The hand listens on `:7000` for the brain's WebSocket. It needs `AEX_HAND_TOKEN` (the per-session
secret) set at launch; the platform sets it. `tools/smoke.sh` builds the image and drives one
session through it end to end.
