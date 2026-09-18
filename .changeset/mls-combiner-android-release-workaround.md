---
"swift-mls": patch
---

Opt `MLS.Combiner`'s founding-commit orchestration out of optimization: a Swift 6.4.0 optimizer bug (SIL ownership verifier, Android cross-compilation only) crashed `-c release` builds of `MLSCombiner`.
