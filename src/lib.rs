#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, clippy::unimplemented)]

pub use ::binrw;

mod error;
pub use error::Error;

mod packet;
pub use packet::{Mac, OpeningCipher, Packet, SealingCipher, PACKET_MAX_SIZE};

mod id;
pub use id::Id;

mod message;
pub use message::{arch, connect, kex, trans, userauth, Message};
