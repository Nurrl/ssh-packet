use super::Mac;

#[cfg(doc)]
use super::Packet;

/// A cipher able to `open` a [`Packet`] and retrieve it's payload.
pub trait OpeningCipher {
    /// The associated error type returned by the `open` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The _Message Authentication Code_ associated to the cipher.
    type Mac: Mac;

    /// Gets a reference to the _Message Authentication Code_ for this [`OpeningCipher`].
    fn mac(&self) -> &Self::Mac;

    /// The size of a [`OpeningCipher`]'s block.
    fn block_size(&self) -> usize;

    /// Decrypt the received `buf` using the [`OpeningCipher`].
    fn decrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<(), Self::Err>;

    /// Compare the received `buf` against the received _Message Authentication Code_.
    fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>) -> Result<(), Self::Err>;

    /// Decompress the received `buf` using the [`OpeningCipher`].
    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;
}

/// A cipher able to `seal` a payload to create a [`Packet`].
pub trait SealingCipher {
    /// The associated error type returned by the `seal` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The _Message Authentication Code_ algorithm associated to the cipher.
    type Mac: Mac;

    /// Gets a reference to the _Message Authentication Code_ algorithm for this [`SealingCipher`].
    fn mac(&self) -> &Self::Mac;

    /// Decompress the `buf` using the [`SealingCipher`].
    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err>;

    /// Pad the `buf` using the [`SealingCipher`] to match MAC's block size.
    fn pad(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;

    /// Encrypt the `buf` using using the [`SealingCipher`].
    fn encrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<(), Self::Err>;

    /// Generate a seal from the HMAC algorithm to produce a _Message Authentication Code_.
    fn seal<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err>;
}
