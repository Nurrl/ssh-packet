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

    /// SSH packet's padding as binary.
    pub padding: Vec<u8>,

    /// SSH packet's Message Authentication Code as binary.
    pub mac: Vec<u8>,
}

impl Packet {
    /// Calculate [`Packet`] `len` field from the structure.
    pub fn size(&self) -> usize {
        std::mem::size_of::<u8>() + self.payload.len() + self.padding.len()
    }

    /// Decrypt the received [`Packet`] from the remote into `T`.
    pub fn decrypt<T, C>(self, cipher: &mut C) -> Result<T, C::Err>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian,
        C: OpeningCipher,
    {
        let payload = cipher.open(self)?;

        Ok(T::read(&mut std::io::Cursor::new(payload))?)
    }

    /// Encrypt `T` to a [`Packet`] to be sent to the remote.
    pub fn encrypt<T, C>(message: &T, cipher: &mut C) -> Result<Self, C::Err>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian,
        C: SealingCipher,
    {
        let mut payload = std::io::Cursor::new(Vec::new());
        message.write(&mut payload)?;

        cipher.seal(payload.into_inner())
    }

    /// Read a [`Packet`] from the provided `reader`.
    pub fn from_reader<R, C>(reader: &mut R, cipher: &mut C) -> Result<Self, C::Err>
    where
        R: std::io::Read,
        C: OpeningCipher,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf[..])?;
        let len = cipher.decrypt_len(buf)?;

        if len as usize > PACKET_MAX_SIZE {
            return Err(binrw::Error::Custom {
                pos: 0x0,
                err: Box::new(format!("Packet size too large, {len} > {PACKET_MAX_SIZE}")),
            })?;
        }

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf[..])?;
        let padlen = cipher.decrypt_padlen(buf)?;

        if padlen as usize > len as usize - 1 {
            return Err(binrw::Error::Custom {
                pos: 0x0,
                err: Box::new(format!("Padding size too large, {padlen} > {} - 1", len)),
            })?;
        }

        let maclen = cipher.mac_len();

        let mut payload = vec![0; len as usize - padlen as usize - std::mem::size_of_val(&padlen)];
        reader.read_exact(&mut payload[..])?;

        let mut padding = vec![0; padlen as usize];
        reader.read_exact(&mut padding[..])?;

        let mut mac = vec![0; maclen];
        reader.read_exact(&mut mac[..])?;

        Ok(Self {
            payload,
            padding,
            mac,
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

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf[..]).await?;
        let padlen = cipher.decrypt_padlen(buf)?;

        if padlen as usize > len as usize - 1 {
            return Err(binrw::Error::Custom {
                pos: 0x0,
                err: Box::new(format!("Padding size too large, {padlen} > {} - 1", len)),
            })?;
        }

        let maclen = cipher.mac_len();

        let mut payload = vec![0; len as usize - padlen as usize - std::mem::size_of_val(&padlen)];
        reader.read_exact(&mut payload[..]).await?;

        let mut padding = vec![0; padlen as usize];
        reader.read_exact(&mut padding[..]).await?;

        let mut mac = vec![0; maclen];
        reader.read_exact(&mut mac[..]).await?;

        Ok(Self {
            payload,
            padding,
            mac,
        })
    }

    /// Write the [`Packet`] to the provided `writer`.
    pub fn to_writer<W, C>(&self, writer: &mut W, cipher: &mut C) -> Result<(), C::Err>
    where
        W: std::io::Write,
        C: SealingCipher,
    {
        writer.write_all(&cipher.encrypt_len(self.size() as u32)?)?;
        writer.write_all(&cipher.encrypt_padlen(self.padding.len() as u8)?)?;
        writer.write_all(&self.payload)?;
        writer.write_all(&self.padding)?;
        writer.write_all(&self.mac)?;

        Ok(())
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

        writer
            .write_all(&cipher.encrypt_len(self.size() as u32)?)
            .await?;
        writer
            .write_all(&cipher.encrypt_padlen(self.padding.len() as u8)?)
            .await?;
        writer.write_all(&self.payload).await?;
        writer.write_all(&self.padding).await?;
        writer.write_all(&self.mac).await?;

        Ok(())
    }
}

/// A cipher able to `open` a [`Packet`] and retrieve it's payload.
pub trait OpeningCipher {
    /// The associated error type returned by the `open` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The size of the Message Authentication Code for this [`OpeningCipher`], in bytes.
    fn mac_len(&self) -> usize;

    /// Decrypt the `len` field in the [`Packet`], if encrypted.
    fn decrypt_len(&mut self, len: [u8; 4]) -> Result<u32, Self::Err> {
        if self.mac_len() == 0 {
            Ok(u32::from_be_bytes(self.decrypt(len)?))
        } else {
            Ok(u32::from_be_bytes(len))
        }
    }

    /// Decrypt the `padlen` field in the [`Packet`].
    fn decrypt_padlen(&mut self, len: [u8; 1]) -> Result<u8, Self::Err> {
        Ok(u8::from_be_bytes(self.decrypt(len)?))
    }

    /// Decrypt a variable length buffer with the [`OpeningCipher`].
    fn decrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<B, Self::Err>;

    /// Verify the Message Authentication Code for this [`Packet`] and get it's payload.
    fn open(&mut self, packet: Packet) -> Result<Vec<u8>, Self::Err>;
}

/// A cipher able to `seal` a payload to create a [`Packet`].
pub trait SealingCipher {
    /// The associated error type returned by the `seal` method.
    type Err: From<binrw::Error> + From<std::io::Error>;

    /// The size of the Message Authentication Code for this [`SealingCipher`], in bytes.
    fn mac_len(&self) -> usize;

    /// Encrypt the `len` field in the [`Packet`], if to be encrypted.
    fn encrypt_len(&mut self, len: u32) -> Result<[u8; 4], Self::Err> {
        if self.mac_len() == 0 {
            Ok(self.encrypt(len.to_be_bytes())?)
        } else {
            Ok(len.to_be_bytes())
        }
    }

    /// Encrypt the `padlen` field in the [`Packet`].
    fn encrypt_padlen(&mut self, len: u8) -> Result<[u8; 1], Self::Err> {
        self.encrypt(len.to_be_bytes())
    }

    /// Encrypt a variable length buffer with the [`SealingCipher`].
    fn encrypt<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<B, Self::Err>;

    /// Sign the Message Authentication Code for this [`Packet`] from it's payload.
    fn seal(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err>;
}
