//! Types defined in the SSH's **architecture** (`SSH-ARCH`) part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

use std::borrow::Cow;

use binrw::binrw;

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`].
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

/// A `mpint` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct MpInt(Bytes);

impl MpInt {
    /// Create new [`MpInt`] from a [`Cow<[u8]>`].
    pub fn new(s: impl Into<Cow<'static, [u8]>>) -> Self {
        Self(Bytes::new(s))
    }
}

impl std::ops::Deref for MpInt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **ASCII**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A `name-list` as defined in the SSH protocol,
/// a `,`-separated list of **ASCII** identifiers,
/// prefixed with it's `size` as a [`u32`].
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct NameList(StringAscii);

impl NameList {
    /// Create new [`NameList`] from a list of names.
    pub fn new(names: &[&str]) -> Self {
        Self(StringAscii::new(names.join(",")))
    }
}

impl<'n> IntoIterator for &'n NameList {
    type Item = &'n str;
    type IntoIter = std::str::Split<'n, char>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.split(',')
    }
}

/// A `boolean` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[brw(big)]
pub struct Bool(
    #[br(map = |n: u8| n > 0)]
    #[bw(map = |b| u8::from(*b))]
    bool,
);

impl std::ops::Not for Bool {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl std::ops::Deref for Bool {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::convert::From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}
