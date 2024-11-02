use std::ops::Deref;

use binrw::{BinRead, BinWrite};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
enum Inner<'b> {
    Owned(Vec<u8>),

    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    Borrowed(&'b [u8]),
}

/// A `string` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
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
    pub const fn owned(value: Vec<u8>) -> Self {
        Self {
            inner: Inner::Owned(value),
        }
    }

    /// Create [`Bytes`] from a _slice_.
    pub const fn borrowed(value: &'b [u8]) -> Self {
        Self {
            inner: Inner::Borrowed(value),
        }
    }

    /// Obtain [`Bytes`] from a reference by borrowing the internal buffer.
    pub fn as_borrow<'a: 'b>(&'a self) -> Bytes<'a> {
        Bytes::borrowed(self)
    }

    /// Extract the buffer into a [`Vec`].
    pub fn into_vec(self) -> Vec<u8> {
        match self.inner {
            Inner::Owned(vec) => vec,
            Inner::Borrowed(slice) => slice.to_vec(),
        }
    }
}

impl Deref for Bytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self.inner {
            Inner::Owned(ref vec) => vec,
            Inner::Borrowed(slice) => slice,
        }
    }
}

impl AsRef<[u8]> for Bytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl PartialEq for Bytes<'_> {
    fn eq(&self, other: &Bytes<'_>) -> bool {
        **self == **other
    }
}

impl Eq for Bytes<'_> {}

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
        let buf = &**self;
        let size = buf.len() as u32;

        size.write_be(writer)?;
        buf.write_options(writer, endian, args)
    }
}
