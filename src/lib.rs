#![doc = include_str!("../README.md")]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo,
    clippy::undocumented_unsafe_blocks
)]
#![forbid(unsafe_code)]

pub use ::binrw;

mod error;
pub use error::Error;

mod packet;
pub use packet::{
    CipherCore, IntoPacket, Mac, OpeningCipher, Packet, SealingCipher, PACKET_MAX_SIZE,
    PACKET_MIN_SIZE,
};

mod id;
pub use id::Id;

pub mod arch;
pub mod connect;
pub mod crypto;
pub mod trans;
pub mod userauth;
