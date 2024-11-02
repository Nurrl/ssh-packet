use std::ops::Deref;

use binrw::binrw;

use super::Bytes;

/// A `string` as defined in the SSH protocol, restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[br(assert(std::str::from_utf8(&self_0).is_ok()))]
pub struct Utf8<'b>(Bytes<'b>);

impl<'b> Utf8<'b> {
    /// Create an [`Utf8`] string from a [`String`].
    pub fn owned(value: String) -> Self {
        Self(Bytes::owned(value.into_bytes()))
    }

    /// Create an [`Utf8`] string from a [`&str`].
    pub const fn borrowed(value: &'b str) -> Self {
        Self(Bytes::borrowed(value.as_bytes()))
    }

    /// Obtain an [`Utf8`] string from a reference by borrowing the internal buffer.
    pub fn as_borrow<'a: 'b>(&'a self) -> Utf8<'a> {
        Self(self.0.as_borrow())
    }

    /// Extract the buffer as a [`String`].
    pub fn into_string(self) -> String {
        String::from_utf8(self.0.into_vec()).expect("The inner buffer contained non UTF-8 data")
    }
}

impl std::fmt::Debug for Utf8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Utf8").field(&&**self).finish()
    }
}

impl std::fmt::Display for Utf8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl Deref for Utf8<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        std::str::from_utf8(&self.0).expect("The inner buffer contained non UTF-8 data")
    }
}

impl AsRef<str> for Utf8<'_> {
    fn as_ref(&self) -> &str {
        self
    }
}

impl From<String> for Utf8<'_> {
    fn from(value: String) -> Self {
        Self::owned(value)
    }
}

impl<'b> From<&'b str> for Utf8<'b> {
    fn from(value: &'b str) -> Self {
        Self::borrowed(value)
    }
}
