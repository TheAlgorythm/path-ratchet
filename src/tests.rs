use crate::prelude::*;
use std::path::PathBuf;

fn non_existing_absolute() -> PathBuf {
    PathBuf::from("/23271d44-a599-4423-bb43-29b89b371ed0")
}

fn assert_single_disallow(path: &str) {
    assert!(SingleComponentPathBuf::new(path).is_none());
}

#[test]
fn single_disallow_parent() {
    assert_single_disallow("../file");
}

#[test]
fn single_strip_current_dir() {
    let mut path = non_existing_absolute();
    let mut replica_path = non_existing_absolute();

    path.push_component(SingleComponentPathBuf::new("./file/.").unwrap());
    replica_path.push("file");

    assert_eq!(path, replica_path);
}
