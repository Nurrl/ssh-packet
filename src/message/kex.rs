//! Helpers for SSH's **kex** part of the protocol.

use binrw::binrw;

use super::arch;

/// The exchange hash for ECDH `kex`, computed as the
/// hash of the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big)]
pub struct EcdhExchange {
    /// Client's identification string (`\r` and `\n` excluded).
    pub v_c: arch::Bytes,

    /// Server's identification string (`\r` and `\n` excluded).
    pub v_s: arch::Bytes,

    /// Payload of the client's `SSH_MSG_KEXINIT` message.
    pub i_c: arch::Bytes,

    /// Payload of the server's `SSH_MSG_KEXINIT` message.
    pub i_s: arch::Bytes,

    /// Server's public host key.
    pub k_s: arch::Bytes,

    /// Client's ephemeral public key octet string.
    pub q_c: arch::Bytes,

    /// Server's ephemeral public key octet string.
    pub q_s: arch::Bytes,

    /// Computed shared secret.
    pub k: arch::MpInt,
}

impl EcdhExchange {
    /// Produce the exchange hash with the specified digest algorithm.
    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    pub fn hash<D: digest::Digest>(&self) -> digest::Output<D> {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed, but it shouldn't have");

        D::digest(&buffer)
    }
}
