use binrw::{
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

/// Maximum size for a SSH packet, coincidentally this is the maximum size for a TCP packet.
pub const PACKET_MAX_SIZE: usize = u16::MAX as usize;

/// A SSH 2.0 binary packet representation, including it's encrypted payload.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[derive(Debug, Clone)]

pub struct Packet {
    /// SSH packet's payload as binary.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Decrypt the received [`Packet`] from the remote into `T`.
    pub fn read<T>(self) -> Result<T, binrw::Error>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian,
    {
        T::read(&mut std::io::Cursor::new(self.payload))
    }

    /// Write `T` to a [`Packet`] to be sent to the remote.
    pub fn write<T>(message: &T) -> Result<Self, binrw::Error>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian,
    {
        let mut payload = std::io::Cursor::new(Vec::new());
        message.write(&mut payload)?;

        Ok(Self {
            payload: payload.into_inner(),
        })
    }

    /// Read a [`Packet`] from the provided asynchronous `reader`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn from_async_reader<R, C>(reader: &mut R, cipher: &mut C) -> Result<Self, C::Err>
    where
        R: futures::io::AsyncRead + Unpin,
        C: OpeningCipher,
    {
        use futures::io::AsyncReadExt;

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf[..]).await?;
        let len = cipher.decrypt_len(buf)?;

        if len as usize > PACKET_MAX_SIZE {
            return Err(binrw::Error::Custom {
                pos: 0x0,
                err: Box::new(format!("Packet size too large, {len} > {PACKET_MAX_SIZE}")),
            })?;
        }

        let mut blob = vec![0; len as usize];
        reader.read_exact(&mut blob[..]).await?;

        let mut mac = vec![0; cipher.mac()];
        reader.read_exact(&mut mac[..]).await?;

        cipher.verify(&blob, mac)?;
        let decrypted = cipher.decrypt(blob)?;

        let (padlen, mut decrypted) =
            decrypted
                .split_first()
                .ok_or_else(|| binrw::Error::Custom {
                    pos: 0x4,
                    err: Box::new(format!("Packet size too small ({len})")),
                })?;

        if *padlen as usize > len as usize - 1 {
            return Err(binrw::Error::Custom {
                pos: 0x4,
                err: Box::new(format!("Padding size too large, {padlen} > {} - 1", len)),
            })?;
        }

        let mut payload = vec![0; len as usize - *padlen as usize - std::mem::size_of_val(padlen)];
        std::io::Read::read_exact(&mut decrypted, &mut payload[..])?;

        let payload = cipher.decompress(payload)?;

        Ok(Self { payload })
    }

    /// Write the [`Packet`] to the provided asynchronous `writer`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn to_async_writer<W, C>(&self, writer: &mut W, cipher: &mut C) -> Result<(), C::Err>
    where
        W: futures::io::AsyncWrite + Unpin,
        C: SealingCipher,
    {
        use futures::AsyncWriteExt;

        let compressed = cipher.compress(&self.payload)?;
        let padded = cipher.pad(compressed)?;
        let encrypted = cipher.encrypt(padded)?;

        writer
            .write_all(&(encrypted.len() as u32).to_be_bytes())
            .await?;

        let signed = cipher.sign(encrypted)?;

        writer.write_all(&signed).await?;

        Ok(())
    }
}

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

    /// Verify the received `blob` using the [`OpeningCipher`],
    /// erroring if the _Message Authentication Code_ does not match.
    fn verify<B: AsRef<[u8]>>(&mut self, blob: B, mac: Vec<u8>) -> Result<(), Self::Err>;

    /// Decrypt the received `blob` using the [`OpeningCipher`].
    fn decrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<B, Self::Err>;

    /// Decompress the received `blob` using the [`OpeningCipher`].
    fn decompress<B: AsRef<[u8]>>(&mut self, blob: B) -> Result<Vec<u8>, Self::Err>;
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

    /// Decompress the blob using the [`SealingCipher`].
    fn compress<B: AsRef<[u8]>>(&mut self, blob: B) -> Result<Vec<u8>, Self::Err>;

    /// Pad the blob using the [`SealingCipher`] to match MAC's block size.
    fn pad(&mut self, blob: Vec<u8>) -> Result<Vec<u8>, Self::Err>;

    /// Encrypt the blob using using the [`SealingCipher`].
    fn encrypt<B: AsMut<[u8]>>(&mut self, blob: B) -> Result<B, Self::Err>;

    /// Sign the blob using using the [`SealingCipher`],
    /// appending a _Message Authentication Code_ if needed.
    fn sign(&mut self, blob: Vec<u8>) -> Result<Vec<u8>, Self::Err>;
}
