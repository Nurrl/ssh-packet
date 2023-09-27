//! # `ssh-packet`
//!
//! Representations of SSH packets interoperable with their binary
//! wire representation.
//!
//! see <https://datatracker.ietf.org/doc/html/rfc4250>.

use binrw::{binrw, helpers};

pub use binrw::{BinRead, BinWrite};

pub mod auth;
pub mod connect;
pub mod transport;

/// An SSH 2.0 packet, including it's payload.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub struct Packet {
    #[bw(assert(payload.len() > u32::MAX as usize, "payload size is too large"), calc = payload.len() as u32)]
    len: u32,

    #[bw(assert(padding.len() > u8::MAX as usize, "padding size is too large"), calc = padding.len() as u8)]
    padding_len: u8,

    /// SSH packet's payload as binary.
    #[br(count = len - padding_len as u32 - 1)]
    pub payload: Vec<u8>,

    /// SSH packet's padding as binary.
    #[br(count = padding_len)]
    pub padding: Vec<u8>,

    /// SSH packet's Message Authentication Code as binary.
    #[br(parse_with = helpers::until_eof)]
    pub mac: Vec<u8>,
}

/// A string per defined in the SSH protocol,
/// prefixed with it's size as a 32-bit integer.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub struct SshString {
    #[bw(calc = payload.len() as u32)]
    len: u32,

    #[br(try_map = String::from_utf8, count = len)]
    #[bw(map = String::as_bytes)]
    payload: String,
}
