//! Types defined in the SSH's **architecture** part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

use std::{borrow::Cow, string::String as StdString};

use binrw::binrw;

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`].
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct String {
    #[bw(calc = payload.len() as u32)]
    len: u32,

    #[br(count = len)]
    payload: Vec<u8>,
}

impl std::ops::Deref for String {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **UTF-8**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct StringUtf8 {
    #[bw(calc = payload.len() as u32)]
    size: u32,

    #[br(try_map = |bytes: Vec<u8>| StdString::from_utf8(bytes).map(Cow::Owned), count = size)]
    #[bw(map = |payload| payload.as_bytes())]
    payload: Cow<'static, str>,
}

impl StringUtf8 {
    pub fn new(s: impl Into<Cow<'static, str>>) -> Self {
        Self { payload: s.into() }
    }
}

impl std::ops::Deref for StringUtf8 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`],
/// restricted to valid **ASCII**.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct StringAscii {
    #[bw(calc = payload.len() as u32)]
    size: u32,

    #[br(try_map = |bytes: Vec<u8>| StdString::from_utf8(bytes).map(Cow::Owned), count = size)]
    #[bw(map = |payload| payload.as_bytes())]
    #[brw(assert(payload.chars().all(|ch| ch.is_ascii())))]
    payload: Cow<'static, str>,
}

impl StringAscii {
    pub fn new(s: impl Into<Cow<'static, str>>) -> Self {
        Self { payload: s.into() }
    }
}

impl std::ops::Deref for StringAscii {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
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

/// A `boolean` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[brw(big)]
pub struct Bool(
    #[br(map = |n: u8| n > 0)]
    #[bw(map = |b| u8::from(*b))]
    pub bool,
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
