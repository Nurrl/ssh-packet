use binrw::{binrw, BinRead, BinWrite};

#[derive(Debug, Clone)]
enum Inner<'b> {
    Owned(Vec<u8>),
    Borrowed(&'b [u8]),
}

/// A `string` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[derive(Debug, Clone)]
pub struct Bytes2<'b> {
    inner: Inner<'b>,
}

impl<'b> Default for Bytes2<'b> {
    fn default() -> Self {
        Self {
            inner: Inner::Owned(Default::default()),
        }
    }
}

impl<'b> Bytes2<'b> {
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

impl AsRef<[u8]> for Bytes2<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            Inner::Owned(vec) => vec,
            Inner::Borrowed(slice) => slice,
        }
    }
}

impl From<Vec<u8>> for Bytes2<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::owned(value)
    }
}

impl<'b> From<&'b [u8]> for Bytes2<'b> {
    fn from(value: &'b [u8]) -> Self {
        Self::borrowed(value)
    }
}

impl BinRead for Bytes2<'_> {
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

impl BinWrite for Bytes2<'_> {
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

/// A `string` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct Bytes {
    #[bw(calc = payload.len() as u32)]
    size: u32,

    #[br(count = size)]
    payload: Vec<u8>,
}

impl Bytes {
    /// Create new [`Bytes`] from a [`Vec`].
    pub fn new(s: impl Into<Vec<u8>>) -> Self {
        Self { payload: s.into() }
    }

    /// Extract the [`Bytes`] into a [`Vec`].
    pub fn into_vec(self) -> Vec<u8> {
        self.payload
    }
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.as_ref()
    }
}

impl std::ops::DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.payload.as_mut()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

impl<T: Into<Vec<u8>>> From<T> for Bytes {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
