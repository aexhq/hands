#!/usr/bin/env bash
# Pushes this working tree to the Linux dev box and runs a command there.
#   tools/dev-sync.sh                      # sync only
#   tools/dev-sync.sh cargo test           # sync, then run in ~/hands on the box
# The box: DEV_HOST (default from .dev-host), user ubuntu, repo at ~/hands.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${DEV_HOST:-$(cat .dev-host 2>/dev/null || true)}"
[[ -n "$HOST" ]] || { echo "set DEV_HOST or write it to .dev-host" >&2; exit 1; }
tar --exclude=./target --exclude=./.git --exclude=./node_modules -czf - . | ssh "ubuntu@$HOST" 'mkdir -p ~/hands && cd ~/hands && tar -xzf -'
if [[ $# -gt 0 ]]; then
  ssh "ubuntu@$HOST" "source ~/.cargo/env && cd ~/hands && $*"
fi
