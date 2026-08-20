#!/usr/bin/env bash
# Builds the hand image and drives one real session through it, proving the guest agent works in
# a plain Docker container. Run on an aarch64 Linux host with docker + the aarch64-gnu target.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=aarch64-unknown-linux-gnu
TOKEN="smoke-$(date +%s)"

echo "== build guest (aarch64-gnu) and Brain client smoke"
rustup target add "$TARGET" >/dev/null 2>&1 || true
cargo build -p hand-guest --release --target "$TARGET"
cargo build -p hand-guest --example smoke --release

echo "== build image"
docker build -f image/Dockerfile --build-arg "BIN=target/$TARGET/release/hand-guest" -t hand:smoke .

echo "== run hand container"
CID=$(docker run -d --rm -p 8080:8080 -e "HAND_TOKEN=$TOKEN" hand:smoke)
trap 'docker logs "$CID" 2>&1 | sed "s/^/[hand] /" | tail -20; docker stop "$CID" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 30); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&-; sleep 1; break; fi
  sleep 0.3
done

echo "== drive a session"
./target/release/examples/smoke "ws://127.0.0.1:8080/" "$TOKEN"
