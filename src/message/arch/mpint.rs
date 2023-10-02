use binrw::binrw;

use super::Bytes;

/// A `mpint` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct MpInt(Bytes);

impl MpInt {
    /// Create new [`MpInt`] from a [`Vec`].
    pub fn new(s: impl Into<Vec<u8>>) -> Self {
        Self(Bytes::new(s))
    }
}

impl std::ops::Deref for MpInt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
