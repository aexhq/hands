#!/bin/sh
set -eu

test "${HAND_LISTEN_FD:-}" != 3
test -e "/proc/self/fd/$HAND_LISTEN_FD"
printf 'provider-fd-preserved\n' >&3
