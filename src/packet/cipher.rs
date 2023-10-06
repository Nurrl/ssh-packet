/// A cipher able to `open` a [`Packet`] and retrieve it's payload.
pub trait OpeningCipher {
    /// The associated error type returned by the `open` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The size of the Message Authentication Code for this [`OpeningCipher`], in bytes.
    fn mac(&self) -> usize;

    /// Decrypt the `len` field in the [`Packet`], if encrypted.
    fn decrypt_len(&mut self, len: [u8; 4]) -> Result<u32, Self::Err> {
        if self.mac() == 0 {
            Ok(u32::from_be_bytes(self.decrypt(len)?))
        } else {
            Ok(u32::from_be_bytes(len))
        }
    }

    /// Decrypt the received `buf` using the [`OpeningCipher`].
    fn decrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<B, Self::Err>;

    /// Decrypt the received `buf` using [`OpeningCipher::decrypt`]
    /// and verify the received `buf` against the _Message Authentication Code_ if needed.
    fn open(&mut self, buf: Vec<u8>, mac: Vec<u8>) -> Result<Vec<u8>, Self::Err>;

    /// Decompress the received `buf` using the [`OpeningCipher`].
    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;
}

/// A cipher able to `seal` a payload to create a [`Packet`].
pub trait SealingCipher {
    /// The associated error type returned by the `seal` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The size of the Message Authentication Code for this [`SealingCipher`], in bytes.
    fn mac(&self) -> usize;

    /// Encrypt the `len` field in the [`Packet`], if to be encrypted.
    fn encrypt_len(&mut self, len: u32) -> Result<[u8; 4], Self::Err> {
        if self.mac() == 0 {
            Ok(self.encrypt(len.to_be_bytes())?)
        } else {
            Ok(len.to_be_bytes())
        }
    }

    /// Decompress the `buf` using the [`SealingCipher`].
    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err>;

    /// Pad the `buf` using the [`SealingCipher`] to match MAC's block size.
    fn pad(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;

    /// Encrypt the `buf` using using the [`SealingCipher`].
    fn encrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<B, Self::Err>;

    /// Encrypt the `buf` using using the [`SealingCipher::encrypt`],
    /// and sign + append a _Message Authentication Code_ if needed.
    fn seal(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err>;
}
