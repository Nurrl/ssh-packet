use std::ops::Deref;

use binrw::binrw;

use super::Bytes;

/// Create an [`Ascii`] string from a literal in _const_-context.
#[doc(hidden)]
#[macro_export]
macro_rules! __ascii__ {
    ($string:literal) => {
        if $string.is_ascii() {
            #[allow(deprecated)]
            $crate::arch::Ascii::borrowed_unchecked($string)
        } else {
            panic!("the literal wasn't ASCII-formatted")
        }
    };
}

pub use __ascii__ as ascii;

/// Errors which can occur when attempting to interpret a string as a ASCII characters.
#[derive(Debug)]
pub struct AsciiError {}

impl std::fmt::Display for AsciiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the input data wasn't ASCII-formatted")
    }
}

impl std::error::Error for AsciiError {}

/// A `string` as defined in the SSH protocol, restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[br(assert(self_0.as_borrow().is_ascii()))]
pub struct Ascii<'b>(Bytes<'b>);

impl<'b> Ascii<'b> {
    /// Create an [`Ascii`] string from a [`String`].
    pub fn owned(value: String) -> Result<Self, AsciiError> {
        if value.is_ascii() {
            Ok(Self(Bytes::owned(value.into_bytes())))
        } else {
            Err(AsciiError {})
        }
    }

    /// Create an [`Ascii`] string from a [`&str`].
    pub const fn borrowed(value: &'b str) -> Result<Self, AsciiError> {
        if value.is_ascii() {
            Ok(Self(Bytes::borrowed(value.as_bytes())))
        } else {
            Err(AsciiError {})
        }
    }

    #[doc(hidden)]
    #[deprecated(
        since = "0.0.0",
        note = "This is an internal function, and is not safe to work with"
    )]
    pub const fn borrowed_unchecked(value: &'b str) -> Self {
        Self(Bytes::borrowed(value.as_bytes()))
    }

    /// Obtain an [`Ascii`] string from a reference by borrowing the internal buffer.
    pub fn as_borrow<'a: 'b>(&'a self) -> Ascii<'a> {
        Self(self.0.as_borrow())
    }

    /// Extract the buffer as a [`String`].
    pub fn into_string(self) -> String {
        String::from_utf8(self.0.into_vec()).expect("The inner buffer contained non UTF-8 data")
    }
}

impl std::fmt::Debug for Ascii<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ascii").field(&&**self).finish()
    }
}

impl std::fmt::Display for Ascii<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl Deref for Ascii<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        std::str::from_utf8(&self.0).expect("The inner buffer contained non UTF-8 data")
    }
}

impl AsRef<str> for Ascii<'_> {
    fn as_ref(&self) -> &str {
        self
    }
}

impl TryFrom<String> for Ascii<'_> {
    type Error = AsciiError;

    fn try_from(value: String) -> Result<Self, AsciiError> {
        Self::owned(value)
    }
}

impl<'b> TryFrom<&'b str> for Ascii<'b> {
    type Error = AsciiError;

    fn try_from(value: &'b str) -> Result<Self, Self::Error> {
        Self::borrowed(value)
    }
}
