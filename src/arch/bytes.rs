use binrw::binrw;

/// A `string` as defined in the SSH protocol,
/// prefixed with it's `size` as a [`u32`].
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
