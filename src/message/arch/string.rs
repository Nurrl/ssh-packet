use std::ops::Deref;

use binrw::binrw;

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`].
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct Bytes {
    #[bw(calc = payload.len() as u32)]
    size: u32,

    #[br(count = size)]
    payload: Vec<u8>,
}

impl Bytes {
    /// Create new [`Bytes`] from a [`Vec`].
    pub fn new(s: impl Into<Vec<u8>>) -> Self {
        Self { payload: s.into() }
    }

    /// Extract the [`Bytes`] into a [`Vec`].
    pub fn into_vec(self) -> Vec<u8> {
        self.payload
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bytes").field(&self.payload).finish()
    }
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

impl std::ops::DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.payload.as_mut()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

impl<T: Into<Vec<u8>>> From<T> for Bytes {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[brw(big, assert(std::str::from_utf8(&self_0.payload).is_ok()))]
pub struct StringUtf8(Bytes);

impl StringUtf8 {
    /// Create new [`StringUtf8`] from a [`String`].
    pub fn new(s: impl Into<String>) -> Self {
        Self(Bytes::new(s.into().into_bytes()))
    }

    /// Views this [`StringUtf8`] as a UTF-8 str.
    pub fn as_str(&self) -> &str {
        self
    }

    /// Converts the [`StringUtf8`] to a [`String`].
    pub fn into_string(self) -> String {
        String::from_utf8(self.0.into_vec())
            .expect("StringUtf8 was constructed in an unexpected way")
    }
}

impl std::fmt::Debug for StringUtf8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StringUtf8").field(&self.deref()).finish()
    }
}

impl std::ops::Deref for StringUtf8 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        std::str::from_utf8(self.0.as_ref())
            .expect("StringUtf8 was constructed in an unexpected way")
    }
}

impl std::ops::DerefMut for StringUtf8 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        std::str::from_utf8_mut(self.0.as_mut())
            .expect("StringUtf8 was constructed in an unexpected way")
    }
}

impl<T: Into<String>> From<T> for StringUtf8 {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **ASCII**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[brw(big, assert(self_0.is_ascii()))]
pub struct StringAscii(StringUtf8);

impl StringAscii {
    /// Create new [`StringAscii`] from a [`String`], stripping any non-UTF8 characters.
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(StringUtf8::new(
            s.as_ref()
                .chars()
                .filter(char::is_ascii)
                .collect::<String>(),
        ))
    }

    /// Views this [`StringAscii`] of ASCII characters as a UTF-8 str.
    pub fn as_str(&self) -> &str {
        self
    }

    /// Converts the [`StringAscii`] to a [`String`].
    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}

impl std::fmt::Debug for StringAscii {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StringAscii").field(&self.deref()).finish()
    }
}

impl std::ops::Deref for StringAscii {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for StringAscii {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: AsRef<str>> From<T> for StringAscii {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
