use binrw::{
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

mod cipher;
pub use cipher::{OpeningCipher, SealingCipher};

mod mac;
pub use mac::Mac;

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

        let mut buf = vec![0; cipher.block_size()];
        reader.read_exact(&mut buf[..]).await?;

        if !cipher.mac().etm() {
            cipher.decrypt(&mut buf[..])?;
        }

        let len = u32::from_be_bytes(
            buf[..4]
                .try_into()
                .expect("The buffer of size 4 is not of size 4"),
        );

        if len as usize > PACKET_MAX_SIZE {
            return Err(binrw::Error::Custom {
                pos: 0x0,
                err: Box::new(format!("Packet size too large, {len} > {PACKET_MAX_SIZE}")),
            })?;
        }

        // Read the rest of the data from the reader
        buf.resize(std::mem::size_of_val(&len) + len as usize, 0);
        reader.read_exact(&mut buf[cipher.block_size()..]).await?;

        let mut mac = vec![0; cipher.mac().size()];
        reader.read_exact(&mut mac[..]).await?;

        if cipher.mac().etm() {
            cipher.open(&buf, mac)?;
            cipher.decrypt(&mut buf[4..])?;
        } else {
            cipher.decrypt(&mut buf[cipher.block_size()..])?;
            cipher.open(&buf, mac)?;
        }

        let (padlen, mut decrypted) =
            buf[4..].split_first().ok_or_else(|| binrw::Error::Custom {
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

        let buf = cipher.pad(compressed)?;
        let mut buf = [(buf.len() as u32).to_be_bytes().to_vec(), buf].concat();

        let (buf, mac) = if cipher.mac().etm() {
            cipher.encrypt(&mut buf[4..])?;
            let mac = cipher.seal(&buf)?;

            (buf, mac)
        } else {
            let mac = cipher.seal(&buf)?;
            cipher.encrypt(&mut buf[..])?;

            (buf, mac)
        };

        writer.write_all(&buf).await?;
        writer.write_all(&mac).await?;

        Ok(())
    }
}
