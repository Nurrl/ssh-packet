//! Types defined in the SSH's **architecture** part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

use std::string::String as StdString;

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

    #[br(try_map = StdString::from_utf8, count = size)]
    #[bw(map = StdString::as_bytes)]
    payload: StdString,
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

    #[br(try_map = StdString::from_utf8, count = size)]
    #[bw(map = StdString::as_bytes)]
    #[brw(assert(payload.chars().all(|ch| ch.is_ascii())))]
    payload: StdString,
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
    bool,
);
