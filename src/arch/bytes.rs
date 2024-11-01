use binrw::{BinRead, BinWrite};

#[derive(Debug, Clone)]
enum Inner<'b> {
    Owned(Vec<u8>),
    Borrowed(&'b [u8]),
}

/// A `string` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[derive(Debug, Clone)]
pub struct Bytes<'b> {
    inner: Inner<'b>,
}

impl<'b> Default for Bytes<'b> {
    fn default() -> Self {
        Self {
            inner: Inner::Owned(Default::default()),
        }
    }
}

impl<'b> Bytes<'b> {
    /// Create [`Bytes`] from a _vector_.
    pub fn owned(value: Vec<u8>) -> Self {
        Self {
            inner: Inner::Owned(value),
        }
    }

    /// Create [`Bytes`] from a _slice_.
    pub fn borrowed(value: &'b [u8]) -> Self {
        Self {
            inner: Inner::Borrowed(value),
        }
    }
}

impl AsRef<[u8]> for Bytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            Inner::Owned(vec) => vec,
            Inner::Borrowed(slice) => slice,
        }
    }
}

impl From<Vec<u8>> for Bytes<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::owned(value)
    }
}

impl<'b> From<&'b [u8]> for Bytes<'b> {
    fn from(value: &'b [u8]) -> Self {
        Self::borrowed(value)
    }
}

impl BinRead for Bytes<'_> {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let size = u32::read_be(reader)?;

        BinRead::read_options(
            reader,
            endian,
            binrw::VecArgs {
                count: size as usize,
                inner: args,
            },
        )
        .map(Self::owned)
    }
}

impl BinWrite for Bytes<'_> {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let buf = self.as_ref();
        let size = buf.len() as u32;

        size.write_be(writer)?;
        buf.write_options(writer, endian, args)
    }
}
