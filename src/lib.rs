//! [`PathBuf::push`] allows any form of path traversal:
//!
//! ```
//! # use std::path::PathBuf;
//! #
//! # #[cfg(unix)]
//! # {
//! let user_input = "/etc/shadow";
//! let mut filename = PathBuf::from("/tmp");
//! filename.push(user_input);
//! assert_eq!(filename, PathBuf::from("/etc/shadow"));
//! # }
//! ```
//!
//! Contrary `<PathBuf as PushPathComponent>::push_component` requires a path with only a single element.
//!
//! ```should_panic
//! use std::path::PathBuf;
//! use path_ratchet::prelude::*;
//!
//! # #[cfg(unix)]
//! # {
//! let user_input = "/etc/shadow";
//! let mut filename = PathBuf::from("/tmp");
//! filename.push_component(SingleComponentPath::new(user_input).unwrap());
//! # }
//! ```

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

/// A safe wrapper for a `PathBuf` with only a single component.
/// This prevents path traversal attacks.
///
/// It allows just a single normal path element and no parent, root directory or prefix like `C:`.
/// Allows reference to the current directory of the path (`.`).
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SingleComponentPathBuf {
    pub(crate) path: PathBuf,
}

impl SingleComponentPathBuf {
    /// It creates the wrapped `SingleComponentPathBuf` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// use path_ratchet::SingleComponentPathBuf;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder: SingleComponentPathBuf = SingleComponentPathBuf::new("foo").unwrap();
    /// let some_valid_file: SingleComponentPathBuf = SingleComponentPathBuf::new("bar.txt").unwrap();
    /// let with_backreference: SingleComponentPathBuf = SingleComponentPathBuf::new("./bar.txt").unwrap();
    /// assert!(SingleComponentPathBuf::new("/etc/shadow").is_none());
    /// # }
    /// ```
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        SingleComponentPath::from(&component)
            .is_valid()
            .then_some(component)
    }
}

impl std::ops::Deref for SingleComponentPathBuf {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for SingleComponentPathBuf {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

/// A safe wrapper for a `Path` with only a single component.
/// This prevents path traversal attacks.
///
/// It allows just a single normal path element and no parent, root directory or prefix like `C:`.
/// Allows reference to the current directory of the path (`.`).
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SingleComponentPath<'p> {
    pub(crate) path: &'p Path,
}

impl<'p> SingleComponentPath<'p> {
    /// It creates the wrapped `SingleComponentPath` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// use path_ratchet::SingleComponentPath;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder: SingleComponentPath = SingleComponentPath::new("foo").unwrap();
    /// let some_valid_file: SingleComponentPath = SingleComponentPath::new("bar.txt").unwrap();
    /// let with_backreference: SingleComponentPath = SingleComponentPath::new("./bar.txt").unwrap();
    /// assert!(SingleComponentPath::new("/etc/shadow").is_none());
    /// # }
    /// ```
    pub fn new<P: AsRef<Path> + ?Sized>(component: &'p P) -> Option<Self> {
        let component = Self {
            path: component.as_ref(),
        };

        component.is_valid().then_some(component)
    }

    pub(crate) fn is_valid(&self) -> bool {
        use std::path::Component;

        let mut components = self
            .path
            .components()
            .filter(|component| !matches!(component, Component::CurDir));

        matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        )
    }
}

impl<'p> From<&'p SingleComponentPathBuf> for SingleComponentPath<'p> {
    fn from(s: &'p SingleComponentPathBuf) -> Self {
        Self { path: &s.path }
    }
}

impl<'p> From<SingleComponentPath<'p>> for SingleComponentPathBuf {
    fn from(s: SingleComponentPath<'p>) -> Self {
        Self {
            path: s.path.to_path_buf(),
        }
    }
}

impl std::ops::Deref for SingleComponentPath<'_> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path
    }
}

impl AsRef<Path> for SingleComponentPath<'_> {
    fn as_ref(&self) -> &Path {
        self.path
    }
}

/// Extension trait for [`PathBuf`] to push only components which don't allow path traversal.
pub trait PushPathComponent {
    /// This allows to push just a [`SingleComponentPathBuf`] to a [`std::path::PathBuf`].
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use path_ratchet::prelude::*;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let mut path = PathBuf::new();
    /// path.push_component(SingleComponentPath::new("foo").unwrap());
    /// path.push_component(&SingleComponentPathBuf::new("bar.txt").unwrap());
    ///
    /// assert_eq!(path, PathBuf::from("foo/bar.txt"));
    /// # }
    /// ```
    fn push_component<'p>(&mut self, component: impl Into<SingleComponentPath<'p>>);
}

impl PushPathComponent for PathBuf {
    fn push_component<'p>(&mut self, component: impl Into<SingleComponentPath<'p>>) {
        self.push(component.into());
    }
}

/// All needed defenitions
pub mod prelude {
    pub use crate::PushPathComponent;
    pub use crate::SingleComponentPath;
    pub use crate::SingleComponentPathBuf;
}
