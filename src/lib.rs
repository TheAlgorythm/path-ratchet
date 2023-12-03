use std::path::PathBuf;

/// A safe wrapper for a path with only a single component.
/// This prevents path traversal attacks.
///
/// It just allows a single normal path element and no parent, root directory or prefix like `C:`.
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SinglePathComponent {
    path: PathBuf,
}

impl SinglePathComponent {
    /// It creates the wrapped `PathComponent` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// # use path_ratchet::SinglePathComponent;
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder: SinglePathComponent = SinglePathComponent::new("foo").unwrap();
    /// let some_valid_file: SinglePathComponent = SinglePathComponent::new("bar.txt").unwrap();
    /// assert!(SinglePathComponent::new("/etc/shadow").is_none());
    /// # }
    /// ```
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        component.is_valid().then_some(component)
    }

    fn is_valid(&self) -> bool {
        use std::path::Component;

        let mut components = self.path.components();
        matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        )
    }
}

impl std::ops::Deref for SinglePathComponent {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<std::path::Path> for SinglePathComponent {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

/// This allows to push just a [`SinglePathComponent`] to a [`std::path::PathBuf`].
///
/// ```
/// use std::path::PathBuf;
/// # use path_ratchet::{SinglePathComponent, PushPathComponent};
/// # #[cfg(unix)]
/// # {
/// let mut path = PathBuf::new();
/// path.push_component(SinglePathComponent::new("foo").unwrap());
/// path.push_component(SinglePathComponent::new("bar.txt").unwrap());
///
/// assert_eq!(path, PathBuf::from("foo/bar.txt"));
/// # }
/// ```
pub trait PushPathComponent {
    fn push_component(&mut self, component: SinglePathComponent);
}

impl PushPathComponent for PathBuf {
    fn push_component(&mut self, component: SinglePathComponent) {
        self.push(component);
    }
}
