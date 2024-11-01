use binrw::binrw;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use super::Bytes;

/// A `mpint` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
pub struct MpInt<'b>(Bytes<'b>);

impl<'b> MpInt<'b> {
    /// Create a [`MpInt`] from _bytes_.
    pub fn from_bytes(bytes: impl Into<Bytes<'b>>) -> Self {
        Self(bytes.into())
    }

    /// Create a [`MpInt`] from a _slice_, copying it if necessary to ensure it is represented as positive.
    pub fn positive(value: &'b [u8]) -> Self {
        match value.first() {
            Some(byte) if *byte >= 0x80 => {
                let mut buffer = vec![0u8; value.len() + 1];
                buffer[1..].copy_from_slice(value);

                Self(Bytes::owned(buffer))
            }
            _ => Self(Bytes::borrowed(value)),
        }
    }
}

impl AsRef<[u8]> for MpInt<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
