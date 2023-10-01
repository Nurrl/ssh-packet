//! Helpers for SSH's **kex** part of the protocol.

use binrw::binrw;

use super::{arch, trans};

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
    pub i_c: trans::KexInit,

    /// Payload of the server's `SSH_MSG_KEXINIT` message.
    pub i_s: trans::KexInit,

    /// Server's public host key.
    pub k_s: arch::Bytes,

    /// Client's ephemeral public key octet string.
    pub q_c: arch::Bytes,

    /// Server's ephemeral public key octet string.
    pub q_s: arch::Bytes,

    /// Computed shared secret.
    pub k: arch::Bytes,
}
