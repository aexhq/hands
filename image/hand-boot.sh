#!/bin/sh
# Kernel-owned separation between the trusted Hand supervisor and every Tool uid.
set -eu

# A Tool shares the VM network namespace, so provider ingress authentication is not sufficient:
# reject its packets before they can reach any supervisor listener address. Also reject replies
# sourced from the control port: a background Tool must not impersonate the endpoint if the
# supervisor dies and releases the listener.
nft add table inet aex_hand
nft 'add chain inet aex_hand output { type filter hook output priority 0; policy accept; }'
nft add rule inet aex_hand output tcp sport 8080 meta skuid != 1001 reject
nft add rule inet aex_hand output oifname "lo" tcp dport 8080 meta skuid != 1001 reject
for address in $(ip -o -4 address show | awk '{print $4}' | cut -d/ -f1); do
  nft add rule inet aex_hand output ip daddr "$address"/32 tcp dport 8080 meta skuid != 1001 reject
done

# A Tool needs neither user nor network namespaces. Disable their unprivileged creation where the
# kernel exposes the controls; the UID firewall is still authoritative when a key is unavailable.
if [ -w /proc/sys/kernel/unprivileged_userns_clone ]; then
  printf '0\n' > /proc/sys/kernel/unprivileged_userns_clone
fi
if [ -w /proc/sys/user/max_user_namespaces ]; then
  printf '0\n' > /proc/sys/user/max_user_namespaces
fi

# Tool environments and the supervisor may hold session secrets. Never persist a process core;
# the live no-respawn canary deliberately aborts the supervisor after its receipt is flushed.
ulimit -c 0

# Engine file operations run in the supervisor and may create workspace parent directories. Keep
# those directories group-writable just like ordinary Tool output so every binding can collaborate
# through the shared workspace GID. Explicit Tool-created 0600 files remain binding-private.
umask 0002

exec setpriv --reuid hand --regid hand --init-groups \
  env HOME=/home/agent USER=hand LOGNAME=hand /usr/local/bin/hand-guest
