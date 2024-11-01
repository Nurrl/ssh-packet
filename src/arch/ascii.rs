use binrw::binrw;

use super::Bytes2;

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
#[derive(Default, Clone)]
#[br(assert(self_0.as_ref().is_ascii()))]
pub struct Ascii<'b>(Bytes2<'b>);

impl<'b> Ascii<'b> {
    /// Create an [`Ascii`] string from a [`String`].
    pub fn owned(value: String) -> Result<Self, AsciiError> {
        if value.is_ascii() {
            Ok(Self(Bytes2::owned(value.into_bytes())))
        } else {
            Err(AsciiError {})
        }
    }

    /// Create an [`Ascii`] string from a [`&str`].
    pub fn borrowed(value: &'b str) -> Result<Self, AsciiError> {
        if value.is_ascii() {
            Ok(Self(Bytes2::borrowed(value.as_bytes())))
        } else {
            Err(AsciiError {})
        }
    }
}

impl std::fmt::Debug for Ascii<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ascii").field(&self.as_ref()).finish()
    }
}

impl std::fmt::Display for Ascii<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for Ascii<'_> {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(self.0.as_ref()).expect("The data wasn't UTF-8 encoded")
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
