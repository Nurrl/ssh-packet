use std::collections::VecDeque;

use binrw::{binrw, BinRead, BinWrite};

use super::{Bytes, Bytes2};

/// A `mpint` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[derive(Debug, Default, Clone)]
pub struct MpInt2<'b>(pub Bytes2<'b>);

impl BinRead for MpInt2<'_> {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        BinRead::read_options(reader, endian, args).map(Self)
    }
}

impl BinWrite for MpInt2<'_> {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let buf = self.0.as_ref();

        // (SSH-ARCH) By convention, a number that is used in modular computations in
        // Z_n SHOULD be represented in the range 0 <= x < n.
        // ---
        // So we clamp the number to a positive one.
        match buf.first() {
            Some(byte) if *byte >= 0x80 => {
                writer.write_all(&[0])?;
            }
            _ => (),
        };

        buf.write_options(writer, endian, args)
    }
}

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

impl AsRef<[u8]> for MpInt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for MpInt {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}
