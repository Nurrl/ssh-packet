//! Helpers for different hashes and signatures encountered through the protocol.

use binrw::binwrite;

use super::{arch, trans};

/// The exchange hash for ECDH, computed as the
/// hash of the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binwrite]
#[derive(Debug)]
#[bw(big)]
pub struct EcdhExchange<'e> {
    /// Client's identification string (`\r` and `\n` excluded).
    pub v_c: &'e arch::Bytes,

    /// Server's identification string (`\r` and `\n` excluded).
    pub v_s: &'e arch::Bytes,

    /// Payload of the client's `SSH_MSG_KEXINIT` message.
    pub i_c: arch::Lengthed<&'e trans::KexInit>,

    /// Payload of the server's `SSH_MSG_KEXINIT` message.
    pub i_s: arch::Lengthed<&'e trans::KexInit>,

    /// Server's public host key.
    pub k_s: &'e arch::Bytes,

    /// Client's ephemeral public key octet string.
    pub q_c: &'e arch::Bytes,

    /// Server's ephemeral public key octet string.
    pub q_s: &'e arch::Bytes,

    /// Computed shared secret.
    pub k: &'e arch::MpInt,
}

impl EcdhExchange<'_> {
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

/// The data that gets _signed_ and _verified_ to prove the possession of the said private key in
/// the `publickey` authentication method, computed from the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-7>.
#[binwrite]
#[derive(Debug)]
#[bw(big)]
pub struct PublickeySignature<'s> {
    /// The session identifier issued by the key-exchange.
    pub session_id: &'s arch::Bytes,

    #[bw(calc = 50)]
    magic: u8,

    /// Username for the auth request.
    pub username: &'s arch::StringUtf8,

    /// Service name to query.
    pub service_name: &'s arch::StringAscii,

    #[bw(calc = "publickey".into())]
    method: arch::StringUtf8,

    #[bw(calc = true.into())]
    signed: arch::Bool,

    /// Public key algorithm's name.
    pub algorithm: &'s arch::Bytes,

    /// Public key blob.
    pub blob: &'s arch::Bytes,
}

impl PublickeySignature<'_> {
    /// Verify the structure against the provided `signature` with the `key`.
    #[cfg(feature = "signature")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
    pub fn verify<S, K: signature::Verifier<S>>(
        &self,
        key: &K,
        signature: &S,
    ) -> signature::Result<()> {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        K::verify(key, &buffer, signature)
    }

    /// Sign the structure with the provided `key` to produce the `signature`.
    #[cfg(feature = "signature")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
    pub fn sign<S, K: signature::Signer<S>>(&self, key: &K) -> S {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        K::sign(key, &buffer)
    }
}
