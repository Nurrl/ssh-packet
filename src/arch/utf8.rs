use binrw::binrw;

use super::Bytes2;

/// A `string` as defined in the SSH protocol, restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone)]
#[br(assert(std::str::from_utf8(self_0.as_ref()).is_ok()))]
pub struct Utf8<'b>(Bytes2<'b>);

impl<'b> Utf8<'b> {
    /// Create an [`Utf8`] string from a [`String`].
    pub fn owned(value: String) -> Self {
        Self(Bytes2::owned(value.into_bytes()))
    }

    /// Create an [`Utf8`] string from a [`&str`].
    pub fn borrowed(value: &'b str) -> Self {
        Self(Bytes2::borrowed(value.as_bytes()))
    }
}

impl std::fmt::Debug for Utf8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Utf8").field(&self.as_ref()).finish()
    }
}

impl std::fmt::Display for Utf8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for Utf8<'_> {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(self.0.as_ref()).expect("The data wasn't UTF-8 encoded")
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
