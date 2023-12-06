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
//! filename.push_component(SingleComponentPathBuf::new(user_input).unwrap());
//! # }
//! ```

#[cfg(test)]
mod tests;

use std::path::PathBuf;

/// A safe wrapper for a path with only a single component.
/// This prevents path traversal attacks.
///
/// It allows just a single normal path element and no parent, root directory or prefix like `C:`.
/// Allows reference to the current directory of the path (`.`).
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SingleComponentPathBuf {
    path: PathBuf,
}

impl SingleComponentPathBuf {
    /// It creates the wrapped `PathComponent` if it's valid.
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

        component.is_valid().then_some(component)
    }

    fn is_valid(&self) -> bool {
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

impl std::ops::Deref for SingleComponentPathBuf {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<std::path::Path> for SingleComponentPathBuf {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

/// Extension trait for [`PathBuf`] to push components individually.
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
    /// path.push_component(SingleComponentPathBuf::new("foo").unwrap());
    /// path.push_component(SingleComponentPathBuf::new("bar.txt").unwrap());
    ///
    /// assert_eq!(path, PathBuf::from("foo/bar.txt"));
    /// # }
    /// ```
    fn push_component(&mut self, component: SingleComponentPathBuf);
}

impl PushPathComponent for PathBuf {
    fn push_component(&mut self, component: SingleComponentPathBuf) {
        self.push(component);
    }
}

/// All needed defenitions
pub mod prelude {
    pub use crate::PushPathComponent;
    pub use crate::SingleComponentPathBuf;
}
