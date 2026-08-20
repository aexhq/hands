# Working in this repository

* The guest is Linux-only (setsid, process groups, /proc). Develop against a Linux box:
  `tools/dev-sync.sh cargo test` pushes this tree and runs there. This machine has no Docker/WSL.
* The ABI and Hand composition ports are defined in `aexhq/brain` and consumed from an immutable
  Brain tag or revision. Never re-describe the wire format here; change it in Brain first, then bump
  the consumed identity. Hands implements Brain's interface; Brain never imports a Hands crate.
* Invariants the guest must hold (see Brain's protocol contract): I1 sealed manifest, I3 opaque
  commands, I6 never wait on pipe EOF, I7 bytes never cross as results (spill + slices), I8 no
  platform credential (presigned URLs only), I9 output is untrusted, I10 connection loss ≠ hand loss.
* Fail fast; plain English in comments. Commit style: `area: imperative summary`.
