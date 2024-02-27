use binrw::{
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

mod cipher;
pub use cipher::{CipherCore, OpeningCipher, SealingCipher};

mod mac;
pub use mac::Mac;

/// Maximum size for a SSH packet, coincidentally this is
/// the maximum size for a TCP packet.
pub const PACKET_MAX_SIZE: usize = u16::MAX as usize;

/// Minimum size for a SSH packet, coincidentally this is
/// the largest block cipher's block-size.
pub const PACKET_MIN_SIZE: usize = 16;

/// A SSH 2.0 binary packet representation, including it's encrypted payload.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[derive(Debug, Clone)]

pub struct Packet {
    /// SSH packet's payload as binary.
    pub payload: Vec<u8>,
}

impl Packet {
    #[deprecated(since = "0.2.2", note = "please use the [`to`] method instead")]
    /// Decrypt the received [`Packet`] from the remote into `T`.
    pub fn read<T>(&self) -> Result<T, binrw::Error>
    where
        T: BinRead + ReadEndian,
        for<'a> T::Args<'a>: Default,
    {
        self.to()
    }

    #[deprecated(since = "0.2.2", note = "please use the [`ToPacket`] trait instead")]
    /// Write `T` to a [`Packet`] to be sent to the remote.
    pub fn write<T>(message: &T) -> Result<Self, binrw::Error>
    where
        for<'a> T: BinWrite<Args<'a> = ()> + WriteEndian,
    {
        message.to_packet()
    }

    /// Try to deserialize the [`Packet`] into `T`.
    pub fn to<T>(&self) -> Result<T, binrw::Error>
    where
        T: BinRead + ReadEndian,
        for<'a> T::Args<'a>: Default,
    {
        T::read(&mut std::io::Cursor::new(&self.payload))
    }

    /// Read a [`Packet`] from the provided asynchronous `reader`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn from_async_reader<R, C>(
        reader: &mut R,
        cipher: &mut C,
        seq: u32,
    ) -> Result<Self, C::Err>
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
            cipher.open(&buf, mac, seq)?;
            cipher.decrypt(&mut buf[4..])?;
        } else {
            cipher.decrypt(&mut buf[cipher.block_size()..])?;
            cipher.open(&buf, mac, seq)?;
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
    pub async fn to_async_writer<W, C>(
        &self,
        writer: &mut W,
        cipher: &mut C,
        seq: u32,
    ) -> Result<(), C::Err>
    where
        W: futures::io::AsyncWrite + Unpin,
        C: SealingCipher,
    {
        use futures::AsyncWriteExt;

        let compressed = cipher.compress(&self.payload)?;

        let padding = cipher.padding(compressed.len());
        let buf = cipher.pad(compressed, padding)?;
        let mut buf = [(buf.len() as u32).to_be_bytes().to_vec(), buf].concat();

        let (buf, mac) = if cipher.mac().etm() {
            cipher.encrypt(&mut buf[4..])?;
            let mac = cipher.seal(&buf, seq)?;

            (buf, mac)
        } else {
            let mac = cipher.seal(&buf, seq)?;
            cipher.encrypt(&mut buf[..])?;

            (buf, mac)
        };

        writer.write_all(&buf).await?;
        writer.write_all(&mac).await?;

        Ok(())
    }
}

/// Allow types implementing [`BinWrite`] to be easily converted to a [`Packet`].
pub trait ToPacket: BinWrite + WriteEndian
where
    for<'a> Self::Args<'a>: Default,
{
    /// Convert the current type to a [`Packet`].
    fn to_packet(&self) -> Result<Packet, binrw::Error> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        self.write(&mut buffer)?;

        Ok(Packet {
            payload: buffer.into_inner(),
        })
    }
}

impl<T> ToPacket for T
where
    T: BinWrite + WriteEndian,
    for<'a> T::Args<'a>: Default,
{
}
