# `Path` Ratchet

!['LGPL 3.0 License' badge](https://img.shields.io/crates/l/path_ratchet?style=for-the-badge&logo=open-source-initiative&cacheSeconds=43600)
!['No AI' badge](https://img.shields.io/badge/No-AI-violet?style=for-the-badge&cacheSeconds=43600)
[![Crates.io](https://img.shields.io/crates/v/path_ratchet?style=for-the-badge&logo=rust)](https://crates.io/crates/path_ratchet)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/TheAlgorythm/path-ratchet/check.yml?branch=MAIN&style=for-the-badge)](https://github.com/TheAlgorythm/path-ratchet/actions?query=workflow%3ARust)
!['Fuzzed & CI Proptests' badge](https://img.shields.io/badge/Fuzzed_&_CI_Proptests-purple?style=for-the-badge&cacheSeconds=43600)
[![crev reviews](https://web.crev.dev/rust-reviews/badge/crev_count/path_ratchet.svg)](https://web.crev.dev/rust-reviews/crate/path_ratchet/)

Prevent path traversal attacks at the type level.

```Rust
use std::path::PathBuf;
use path_ratchet::prelude::*;

let user_input = "/etc/shadow";
let mut filename = PathBuf::from("/tmp");
filename.push_component(SingleComponentPath::new(user_input).unwrap());
```

For security reasons, this crate follows the principle ["Parse, don’t validate"](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) , making it fairly simple yet effective.
There are no undefined edge cases.
Every case can be seen or deduced from the doctests.
Fuzzing and property-based testing ensure these assumptions are met and guaranteeing the general security of the crate.
