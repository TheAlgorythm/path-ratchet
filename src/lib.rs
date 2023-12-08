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

use std::{
    borrow::Borrow,
    path::{Path, PathBuf},
};

macro_rules! impl_buf_traits {
    ($path_buf:ty) => {
        impl AsRef<Path> for $path_buf {
            fn as_ref(&self) -> &Path {
                &self.path
            }
        }
    };
}

macro_rules! impl_ref_path_traits {
    ($path_ref:ty) => {
        impl std::ops::Deref for $path_ref {
            type Target = Path;

            fn deref(&self) -> &Self::Target {
                &self.path
            }
        }

        impl AsRef<Self> for $path_ref {
            fn as_ref(&self) -> &Self {
                self
            }
        }

        impl AsRef<Path> for $path_ref {
            fn as_ref(&self) -> &Path {
                &self.path
            }
        }
    };
}

macro_rules! impl_conv_traits {
    ($path_buf:ty, $path_ref:ty) => {
        impl Borrow<$path_ref> for $path_buf {
            #[allow(unsafe_code)]
            #[allow(clippy::as_conversions)]
            fn borrow(&self) -> &$path_ref {
                // SAFETY: same reprensentation
                unsafe { &*(self.path.as_path() as *const Path as *const $path_ref) }
            }
        }

        impl ToOwned for $path_ref {
            type Owned = $path_buf;

            fn to_owned(&self) -> Self::Owned {
                Self::Owned {
                    path: self.path.to_path_buf(),
                }
            }
        }

        impl std::ops::Deref for $path_buf {
            type Target = $path_ref;

            fn deref(&self) -> &Self::Target {
                self.borrow()
            }
        }

        impl AsRef<$path_ref> for $path_buf {
            fn as_ref(&self) -> &$path_ref {
                self.borrow()
            }
        }
    };
}

/// A safe wrapper for a `PathBuf` with only a single component.
/// This prevents path traversal attacks.
///
/// The owned variant of [`SingleComponentPath`].
/// There is [`MultiComponentPathBuf`] when multiple components should be allowed.
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
    /// let some_valid_folder = SingleComponentPathBuf::new("foo").unwrap();
    /// let some_valid_file = SingleComponentPathBuf::new("bar.txt").unwrap();
    /// let with_backreference = SingleComponentPathBuf::new("./bar.txt").unwrap();
    /// assert!(SingleComponentPathBuf::new("foo/bar.txt").is_none());
    /// assert!(SingleComponentPathBuf::new("..").is_none());
    /// assert!(SingleComponentPathBuf::new("/").is_none());
    /// assert!(SingleComponentPathBuf::new("/etc/shadow").is_none());
    /// # }
    /// ```
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        component.is_valid().then_some(component)
    }
}

impl_buf_traits! {SingleComponentPathBuf}

/// A safe wrapper for a `Path` with only a single component.
/// This prevents path traversal attacks.
///
/// The borrowed variant of [`SingleComponentPathBuf`].
/// There is [`MultiComponentPath`] when multiple components should be allowed.
///
/// It allows just a single normal path element and no parent, root directory or prefix like `C:`.
/// Allows reference to the current directory of the path (`.`).
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(transparent)]
pub struct SingleComponentPath {
    pub(crate) path: Path,
}

impl SingleComponentPath {
    /// It creates the wrapped `SingleComponentPath` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// use path_ratchet::SingleComponentPath;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder = SingleComponentPath::new("foo").unwrap();
    /// let some_valid_file = SingleComponentPath::new("bar.txt").unwrap();
    /// let with_backreference = SingleComponentPath::new("./bar.txt").unwrap();
    /// assert!(SingleComponentPath::new("foo/bar.txt").is_none());
    /// assert!(SingleComponentPath::new("..").is_none());
    /// assert!(SingleComponentPath::new("/").is_none());
    /// assert!(SingleComponentPath::new("/etc/shadow").is_none());
    /// # }
    /// ```
    #[allow(unsafe_code)]
    #[allow(clippy::as_conversions)]
    pub fn new<P: AsRef<Path> + ?Sized>(component: &P) -> Option<&Self> {
        // SAFETY: same reprensentation
        let component = unsafe { &*(component.as_ref() as *const Path as *const Self) };

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

impl_ref_path_traits! {SingleComponentPath}
impl_conv_traits! {SingleComponentPathBuf, SingleComponentPath}

/// A safe wrapper for a `PathBuf`.
/// This prevents path traversal attacks.
///
/// The owned variant of [`MultiComponentPath`].
/// There is [`SingleComponentPathBuf`] when only a single component should be allowed.
///
/// It allows just normal path elements and no parent, root directory or prefix like `C:`.
/// Further allowed are references to the current directory of the path (`.`).
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct MultiComponentPathBuf {
    pub(crate) path: PathBuf,
}

impl MultiComponentPathBuf {
    /// It creates the wrapped `MultiComponentPathBuf` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// use path_ratchet::MultiComponentPathBuf;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder = MultiComponentPathBuf::new("foo").unwrap();
    /// let some_valid_file = MultiComponentPathBuf::new("bar.txt").unwrap();
    /// let with_backreference = MultiComponentPathBuf::new("./bar.txt").unwrap();
    /// let multi = MultiComponentPathBuf::new("foo/bar.txt").unwrap();
    /// assert!(MultiComponentPathBuf::new("..").is_none());
    /// assert!(MultiComponentPathBuf::new("/").is_none());
    /// assert!(MultiComponentPathBuf::new("/etc/shadow").is_none());
    /// # }
    /// ```
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        MultiComponentPath::from(&component)
            .is_valid()
            .then_some(component)
    }
}

impl std::ops::Deref for MultiComponentPathBuf {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for MultiComponentPathBuf {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

/// A safe wrapper for a `Path`.
/// This prevents path traversal attacks.
///
/// The borrowed variant of [`MultiComponentPathBuf`].
/// There is [`SingleComponentPath`] when only a single component should be allowed.
///
/// It allows just normal path elements and no parent, root directory or prefix like `C:`.
/// Further allowed are references to the current directory of the path (`.`).
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct MultiComponentPath<'p> {
    pub(crate) path: &'p Path,
}

impl<'p> MultiComponentPath<'p> {
    /// It creates the wrapped `MultiComponentPath` if it's valid.
    /// Otherwise it will return `None`.
    ///
    /// ```
    /// use path_ratchet::MultiComponentPath;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let some_valid_folder = MultiComponentPath::new("foo").unwrap();
    /// let some_valid_file = MultiComponentPath::new("bar.txt").unwrap();
    /// let with_backreference = MultiComponentPath::new("./bar.txt").unwrap();
    /// let multi = MultiComponentPath::new("foo/bar.txt").unwrap();
    /// assert!(MultiComponentPath::new("..").is_none());
    /// assert!(MultiComponentPath::new("/").is_none());
    /// assert!(MultiComponentPath::new("/etc/shadow").is_none());
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

        self.path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    }
}

impl<'p> From<&'p MultiComponentPathBuf> for MultiComponentPath<'p> {
    fn from(s: &'p MultiComponentPathBuf) -> Self {
        Self { path: &s.path }
    }
}

impl<'p> From<MultiComponentPath<'p>> for MultiComponentPathBuf {
    fn from(s: MultiComponentPath<'p>) -> Self {
        Self {
            path: s.path.to_path_buf(),
        }
    }
}

impl std::ops::Deref for MultiComponentPath<'_> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path
    }
}

impl AsRef<Path> for MultiComponentPath<'_> {
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
    /// path.push_component(SingleComponentPathBuf::new("bar.txt").unwrap());
    ///
    /// assert_eq!(path, PathBuf::from("foo/bar.txt"));
    /// # }
    /// ```
    fn push_component(&mut self, component: impl AsRef<SingleComponentPath>);
    /// ```
    /// use std::path::PathBuf;
    /// use path_ratchet::prelude::*;
    ///
    /// # #[cfg(unix)]
    /// # {
    /// let mut path = PathBuf::new();
    /// path.push_components(MultiComponentPath::new("foo/bar.txt").unwrap());
    ///
    /// assert_eq!(path, PathBuf::from("foo/bar.txt"));
    /// # }
    /// ```
    fn push_components<'p>(&mut self, component: impl Into<MultiComponentPath<'p>>);
}

impl PushPathComponent for PathBuf {
    fn push_component(&mut self, component: impl AsRef<SingleComponentPath>) {
        self.push(component.as_ref());
    }

    fn push_components<'p>(&mut self, component: impl Into<MultiComponentPath<'p>>) {
        self.push(component.into());
    }
}

/// All needed defenitions
pub mod prelude {
    pub use crate::PushPathComponent;

    pub use crate::SingleComponentPath;
    pub use crate::SingleComponentPathBuf;

    pub use crate::MultiComponentPath;
    pub use crate::MultiComponentPathBuf;
}
