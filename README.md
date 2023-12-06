# `Path` Ratchet

![LGPL 3.0 License](https://img.shields.io/crates/l/path_ratchet?style=for-the-badge&logo=open-source-initiative)
[![Crates.io](https://img.shields.io/crates/v/path_ratchet?style=for-the-badge&logo=rust)](https://crates.io/crates/path_ratchet)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/TheAlgorythm/path-ratchet/check.yml?branch=MAIN&style=for-the-badge)](https://github.com/TheAlgorythm/path-ratchet/actions?query=workflow%3ARust)
[![crev reviews](https://web.crev.dev/rust-reviews/badge/crev_count/path_ratchet.svg)](https://web.crev.dev/rust-reviews/crate/path_ratchet/)

Prevent path traversal attacks at type level.

```Rust
use std::path::PathBuf;
use path_ratchet::prelude::*;

let user_input = "/etc/shadow";
let mut filename = PathBuf::from("/tmp");
filename.push_component(SingleComponentPathBuf::new(user_input).unwrap());
```
