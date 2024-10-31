//! Facilities to produce some of the _exchange hashes_.

use binrw::binwrite;

use super::Lengthed;
use crate::{arch, trans};

/// The exchange hash for ECDH, computed as the
/// hash of the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binwrite]
#[derive(Debug)]
#[bw(big)]
pub struct Ecdh<'e> {
    /// Client's identification string (`\r` and `\n` excluded).
    pub v_c: &'e arch::Bytes,

    /// Server's identification string (`\r` and `\n` excluded).
    pub v_s: &'e arch::Bytes,

    /// Payload of the client's `SSH_MSG_KEXINIT` message.
    pub i_c: Lengthed<&'e trans::KexInit>,

    /// Payload of the server's `SSH_MSG_KEXINIT` message.
    pub i_s: Lengthed<&'e trans::KexInit>,

    /// Server's public host key.
    pub k_s: &'e arch::Bytes,

    /// Client's ephemeral public key octet string.
    pub q_c: &'e arch::Bytes,

    /// Server's ephemeral public key octet string.
    pub q_s: &'e arch::Bytes,

    /// Computed shared secret.
    pub k: &'e arch::MpInt,
}

impl Ecdh<'_> {
    /// Produce the exchange hash with the specified digest algorithm.
    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    pub fn hash<D: digest::Digest>(&self) -> digest::Output<D> {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        D::digest(&buffer)
    }
}
