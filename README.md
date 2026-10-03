# `Path` Ratchet

!['LGPL 3.0 License' badge](https://img.shields.io/crates/l/path_ratchet?style=for-the-badge&logo=open-source-initiative&cacheSeconds=43600)
!['No AI' badge](https://img.shields.io/badge/No-AI-violet?style=for-the-badge&cacheSeconds=43600)
[![Crates.io](https://img.shields.io/crates/v/path_ratchet?style=for-the-badge&logo=rust)](https://crates.io/crates/path_ratchet)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/TheAlgorythm/path-ratchet/check.yml?branch=MAIN&style=for-the-badge)](https://github.com/TheAlgorythm/path-ratchet/actions?query=workflow%3ARust)
!['Fuzzed & CI Proptests' badge](https://img.shields.io/badge/Fuzzed_&_CI_Proptests-purple?style=for-the-badge&cacheSeconds=43600)

Prevent path traversal attacks at the type level.

```Rust
use std::path::PathBuf;
use path_ratchet::prelude::*;

let user_input = "/etc/shadow";
let mut filename = PathBuf::from("/tmp");
filename.push_component(SingleComponentPath::new(user_input).unwrap());
```

`path_ratchet` is effective against classic semantic path traversals where the path is an untrusted input in the threat model.
Nevertheless, in threat models where the attacker has access to the file system (for example, if they can create symlinks), this approach is inadequate and must be supplemented with sandboxing and/or a capability-based approach (for example, the `cap-std` crate).
Other crates targeting path traversal do not differentiate between these attacks properly and attempt to mitigate them all at once.
However, the necessary mitigation depends on the threat model, and due to TOCTOU, the ideal times for the two mitigations are not the same.
Therefore, these mitigations should not be conflated.

For security reasons, this crate adheres to the principle ['Parse, don’t validate'](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/), making it fairly simple yet effective.
There are no undefined edge cases.
Every case can be seen or deduced from the doctests.
Fuzzing and property-based testing ensure that these assumptions are met, thereby guaranteeing the general security of the crate.
