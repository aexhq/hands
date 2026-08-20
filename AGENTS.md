# Working in this repository

- The guest is Linux-only and relies on process groups, signals, and `/proc`. Run its full suite on
  Linux.
- The ABI and Hand composition ports belong to `aexhq/brain` and are consumed from one immutable
  Brain revision. Change the protocol in Brain first, then update every pin here. Hands implements
  Brain's ports; Brain never imports a Hands crate.
- Preserve the protocol invariants: seal the tool manifest, treat commands as opaque, never wait on
  pipe EOF, keep file bytes out of tool results, use presigned URLs instead of platform credentials,
  treat output as untrusted, and distinguish connection loss from Hand loss.
- Fail fast, keep comments self-contained, and use plain English.
- Commit style: `area: imperative summary`.
