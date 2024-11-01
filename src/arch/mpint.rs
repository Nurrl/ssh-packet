use binrw::{BinRead, BinWrite};

use super::Bytes;

/// A `mpint` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[derive(Debug, Default, Clone)]
pub struct MpInt<'b>(pub Bytes<'b>);

impl BinRead for MpInt<'_> {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        BinRead::read_options(reader, endian, args).map(Self)
    }
}

impl BinWrite for MpInt<'_> {
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
