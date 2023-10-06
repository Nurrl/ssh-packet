use super::{Mac, PACKET_MIN_SIZE};

#[cfg(doc)]
use super::Packet;

const MIN_PAD_SIZE: usize = 4;
const MIN_ALIGN: usize = 8;

/// A trait with common methods and associated types involved
/// in the manipulation of [`OpeningCipher`] and [`SealingCipher`].
pub trait CipherCore {
    /// The associated error type returned by the `open` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The _Message Authentication Code_ associated to the cipher.
    type Mac: Mac;

    /// Gets a reference to the _Message Authentication Code_ for this [`CipherCore`].
    fn mac(&self) -> &Self::Mac;

    /// The size of a [`CipherCore`]'s block.
    fn block_size(&self) -> usize;

    /// Calculate the necessary padding size for the provided payload `size`.
    fn padding(&self, payload: usize) -> u8 {
        let align = self.block_size().max(MIN_ALIGN);

        let size = if self.mac().etm() {
            std::mem::size_of::<u8>() + payload
        } else {
            std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + payload
        };
        let padding = align - size % align;

        let padding = if padding < MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.block_size().max(PACKET_MIN_SIZE) {
            (padding + align) as u8
        } else {
            padding as u8
        }
    }
}

/// A cipher able to `open` a [`Packet`] and retrieve it's payload.
pub trait OpeningCipher: CipherCore {
    /// Decrypt the received `buf` using the [`OpeningCipher`].
    fn decrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<(), Self::Err>;

    /// Compare the received `buf` against the received _Message Authentication Code_.
    fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>, seq: u32) -> Result<(), Self::Err>;

    /// Decompress the received `buf` using the [`OpeningCipher`].
    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;
}

/// A cipher able to `seal` a payload to create a [`Packet`].
pub trait SealingCipher: CipherCore {
    /// Decompress the `buf` using the [`SealingCipher`].
    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err>;

    /// Pad the `buf` to match [`SealingCipher`]'s block size with random data,
    /// by increasing it by `padding` bytes and prefixing the `buf` it with it's len.
    fn pad(&mut self, buf: Vec<u8>, padding: u8) -> Result<Vec<u8>, Self::Err>;

    /// Encrypt the `buf` using using the [`SealingCipher`].
    fn encrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<(), Self::Err>;

    /// Generate a seal from the HMAC algorithm to produce a _Message Authentication Code_.
    fn seal<B: AsRef<[u8]>>(&mut self, buf: B, seq: u32) -> Result<Vec<u8>, Self::Err>;
}
