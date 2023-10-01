use binrw::{
    binrw,
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

use crate::Error;

/// A SSH 2.0 binary packet representation, including it's encrypted payload.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big)]
#[br(import(mac_len: usize))]
pub struct Packet {
    #[bw(try_calc = self.size().try_into())]
    len: u32,

    #[bw(try_calc = padding.len().try_into())]
    padding_len: u8,

    /// SSH packet's payload as binary.
    #[br(count = len - padding_len as u32 - std::mem::size_of::<u8>() as u32)]
    pub payload: Vec<u8>,

    /// SSH packet's padding as binary.
    #[br(count = padding_len)]
    pub padding: Vec<u8>,

    /// SSH packet's Message Authentication Code as binary.
    #[br(count = mac_len)]
    pub mac: Vec<u8>,
}

impl Packet {
    /// Calculate [`Packet`] size field from the structure.
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
    pub fn from_reader<R, C>(reader: &mut R, cipher: &C) -> Result<Self, Error>
    where
        R: std::io::Read + std::io::Seek,
        C: OpeningCipher,
    {
        Ok(Self::read_args(reader, (cipher.size(),))?)
    }

    /// Read a [`Packet`] from the provided asynchronous `reader`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn from_async_reader<R, C>(reader: &mut R, cipher: &C) -> Result<Self, Error>
    where
        R: futures::io::AsyncRead + Unpin,
        C: OpeningCipher,
    {
        use futures::io::AsyncReadExt;

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await?;

        let len = u32::from_be_bytes(buf);
        let size = std::mem::size_of::<u32>() + len as usize + cipher.size();

        let mut buf = buf.to_vec();
        buf.resize(size, 0);

        reader
            .read_exact(&mut buf[std::mem::size_of::<u32>()..])
            .await?;

        Ok(Self::read_args(
            &mut std::io::Cursor::new(buf),
            (cipher.size(),),
        )?)
    }

    /// Write the [`Packet`] to the provided `writer`.
    pub fn to_writer<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: std::io::Write + std::io::Seek,
    {
        Ok(self.write(writer)?)
    }

    /// Write the [`Packet`] to the provided asynchronous `writer`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn to_async_writer<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: futures::io::AsyncWrite + Unpin,
    {
        use futures::io::AsyncWriteExt;

        let size = std::mem::size_of::<u32>()
            + std::mem::size_of::<u8>()
            + self.payload.len()
            + self.padding.len()
            + self.mac.len();

        let mut buf = std::io::Cursor::new(vec![0u8; size]);
        self.write(&mut buf)?;

        Ok(writer.write_all(&buf.into_inner()).await?)
    }
}

/// A cipher able to `open` a [`Packet`] and retrieve it's payload.
pub trait OpeningCipher {
    /// The associated error type returned by the `open` method.
    type Err: From<binrw::Error>;

    /// The size of the Message Authentication Code for this [`OpeningCipher`], in bytes.
    fn size(&self) -> usize;

    /// Transform the [`Packet`] using the [`OpeningCipher`] into it's decrypted `payload`.
    fn open(&mut self, packet: Packet) -> Result<Vec<u8>, Self::Err>;
}

/// A cipher able to `seal` a payload to create a [`Packet`].
pub trait SealingCipher {
    /// The associated error type returned by the `seal` method.
    type Err: From<binrw::Error>;

    /// Transform the `payload` into it's encrypted [`Packet`] using the [`SealingCipher`].
    fn seal(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_traits_are_object_safe() {
        struct Dummy;

        impl OpeningCipher for Dummy {
            type Err = Box<dyn std::error::Error>;

            fn size(&self) -> usize {
                16
            }

            fn open(&mut self, _packet: Packet) -> Result<Vec<u8>, Self::Err> {
                todo!()
            }
        }

        impl SealingCipher for Dummy {
            type Err = Box<dyn std::error::Error>;

            fn seal(&mut self, _payload: Vec<u8>) -> Result<Packet, Self::Err> {
                todo!()
            }
        }

        let _: &dyn OpeningCipher<Err = Box<dyn std::error::Error>> = &Dummy;
        let _: &dyn SealingCipher<Err = Box<dyn std::error::Error>> = &Dummy;
    }
}
