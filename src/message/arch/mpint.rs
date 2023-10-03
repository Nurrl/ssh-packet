use std::collections::VecDeque;

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
    pub fn new(value: impl Into<VecDeque<u8>>) -> Self {
        let mut vec = value.into();

        match vec.front() {
            Some(byte) if *byte >= 0x80 => {
                vec.push_front(0);
            }
            _ => (),
        };

        Self(Bytes::new(vec))
    }
}

impl std::ops::Deref for MpInt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for MpInt {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}
