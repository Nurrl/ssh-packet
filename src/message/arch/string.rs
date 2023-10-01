use std::{borrow::Cow, ops::Deref};

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

    #[br(map = Cow::Owned, count = size)]
    #[bw(map = |payload| payload.as_ref())]
    payload: Cow<'static, [u8]>,
}

impl Bytes {
    /// Create new [`Bytes`] from a [`Cow<[u8]>`].
    pub fn new(s: impl Into<Cow<'static, [u8]>>) -> Self {
        Self { payload: s.into() }
    }

    /// Unpacks the `string` into a [`Vec`].
    pub fn into_vec(self) -> Vec<u8> {
        self.payload.into_owned()
    }
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bytes").field(&self.payload).finish()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self {
            payload: value.into(),
        }
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
}

impl std::ops::Deref for StringUtf8 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        std::str::from_utf8(self.0.as_ref())
            .expect("StringUtf8 was constructed in an unexpected way")
    }
}

impl std::fmt::Debug for StringUtf8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StringUtf8").field(&self.deref()).finish()
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
    /// Create new [`StringAscii`] from a [`String`].
    pub fn new(s: impl Into<String>) -> Self {
        Self(StringUtf8::new(s))
    }
}

impl std::ops::Deref for StringAscii {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for StringAscii {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StringAscii").field(&self.deref()).finish()
    }
}
