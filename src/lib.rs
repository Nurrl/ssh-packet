#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, clippy::unimplemented)]

pub use ::binrw;

mod error;
pub use error::Error;

mod packet;
pub use packet::{
    CipherCore, Mac, OpeningCipher, Packet, SealingCipher, PACKET_MAX_SIZE, PACKET_MIN_SIZE,
};

mod id;
pub use id::SshId;

mod message;
pub use message::{arch, connect, kex, trans, userauth, Message};
