use crate::prelude::*;
use std::path::PathBuf;

fn non_existing_absolute() -> PathBuf {
    PathBuf::from("/23271d44-a599-4423-bb43-29b89b371ed0")
}

fn assert_single_disallow(path: &str) {
    assert!(SingleComponentPathBuf::new(path).is_none());
}

fn assert_multi_disallow(path: &str) {
    assert!(MultiComponentPathBuf::new(path).is_none());
}

#[test]
fn single_disallow_parent() {
    assert_single_disallow("../file");
}

#[test]
fn multi_disallow_parent() {
    assert_multi_disallow("../file");
    assert_multi_disallow("../folder/file");
}

#[test]
fn single_strip_current_dir() {
    let mut path = non_existing_absolute();
    let mut replica_path = non_existing_absolute();

    path.push_component(SingleComponentPath::new("./file/.").unwrap());
    replica_path.push("file");

    assert_eq!(path, replica_path);
}

#[test]
fn multi_strip_current_dir() {
    let mut path = non_existing_absolute();
    let mut replica_path = non_existing_absolute();

    path.push_components(MultiComponentPath::new("./folder/./file/.").unwrap());
    replica_path.push("folder/file");

    assert_eq!(path, replica_path);
}

mod property {
    use super::*;
    use normalize_path::NormalizePath;
    use proptest::prelude::*;

    fn count_components(p: &std::path::Path) -> usize {
        p.components().count()
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore)]
        fn single(appending in any::<PathBuf>()) {
            let base_path = non_existing_absolute();
            let mut path = non_existing_absolute();
            let base_components = count_components(&base_path);
            let expected_components = base_components.strict_add(count_components(&appending));
            if let Some(component) = SingleComponentPathBuf::new(appending.clone()) {
                let path = {
                    path.push_component(component);

                    path
                };

                let normalized_path = path.normalize();

                prop_assert!(base_components <= count_components(&normalized_path));
                prop_assert!(base_components + 1 >= count_components(&normalized_path));
                prop_assert_eq!(&path, &normalized_path);

                prop_assert_eq!(
                    base_path.components().collect::<Vec<_>>(),
                    normalized_path.components().take(base_components).collect::<Vec<_>>()
                );

                prop_assert_eq!(
                    appending
                        .components()
                        .filter(|component| component != &std::path::Component::CurDir)
                        .collect::<Vec<_>>(),
                    normalized_path.components().skip(base_components).collect::<Vec<_>>()
                );
            } else {
                let path = {
                    path.push(appending.clone());

                    path
                };

                let normalized_path = path.normalize();

                prop_assert!(
                    expected_components > count_components(&normalized_path)
                    || path != normalized_path
                    || appending
                        .components()
                        .filter(|component| component != &std::path::Component::CurDir)
                        .count() != 1
                );
            }
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn multi(appending in any::<PathBuf>()) {
            let base_path = non_existing_absolute();
            let mut path = non_existing_absolute();
            let base_components = count_components(&base_path);
            let expected_components = base_components.strict_add(count_components(&appending));
            if let Some(component) = MultiComponentPathBuf::new(appending.clone()) {
                let path = {
                    path.push_components(component);

                    path
                };

                let normalized_path = path.normalize();

                prop_assert!(base_components <= count_components(&normalized_path));
                prop_assert_eq!(&path, &normalized_path);

                prop_assert_eq!(
                    base_path.components().collect::<Vec<_>>(),
                    normalized_path.components().take(base_components).collect::<Vec<_>>()
                );

                prop_assert_eq!(
                    appending
                        .components()
                        .filter(|component| component != &std::path::Component::CurDir)
                        .collect::<Vec<_>>(),
                    normalized_path.components().skip(base_components).collect::<Vec<_>>()
                );
            } else {
                let path = {
                    path.push(appending);

                    path
                };

                let normalized_path = path.normalize();

                prop_assert!(
                    expected_components > count_components(&normalized_path)
                    || path != normalized_path
                );
            }
        }
    }
}
