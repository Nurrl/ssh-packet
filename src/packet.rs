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
#[derive(Debug)]
#[brw(big)]
#[br(import(mac_len: usize))]
pub struct Packet {
    #[bw(assert(payload.len() > u32::MAX as usize, "payload size is too large"), calc = payload.len() as u32)]
    len: u32,

    #[bw(assert(padding.len() > u8::MAX as usize, "padding size is too large"), calc = padding.len() as u8)]
    padding_len: u8,

    /// SSH packet's payload as binary.
    #[br(count = len - padding_len as u32 - 1)]
    pub payload: Vec<u8>,

    /// SSH packet's padding as binary.
    #[br(count = padding_len)]
    pub padding: Vec<u8>,

    /// SSH packet's Message Authentication Code as binary.
    #[br(count = mac_len)]
    pub mac: Vec<u8>,
}

impl Packet {
    /// Decrypt the received [`Packet`] from the remote into `T`.
    pub fn decrypt<T, C>(self, cipher: &mut C) -> Result<T, Error<C::Err>>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian,
        C: Cipher,
    {
        let payload = cipher.decrypt(self).map_err(Error::Cipher)?;

        Ok(T::read(&mut std::io::Cursor::new(payload))?)
    }

    /// Encrypt `T` to a [`Packet`] to be sent to the remote.
    pub fn encrypt<T, C>(message: T, cipher: &mut C) -> Result<Self, Error<C::Err>>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian,
        C: Cipher,
    {
        let mut payload = std::io::Cursor::new(Vec::new());
        message.write(&mut payload)?;

        cipher.encrypt(payload.into_inner()).map_err(Error::Cipher)
    }

    /// Read a [`Packet`] from the provided `reader`.
    pub fn from_reader<R, E, C>(reader: &mut R, cipher: &C) -> Result<Self, Error<E>>
    where
        R: std::io::Read + std::io::Seek,
        C: Cipher,
    {
        Ok(Self::read_args(reader, (cipher.size(),))?)
    }

    /// Read a [`Packet`] from the provided asynchronous `reader`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn from_async_reader<R, E, C>(reader: &mut R, cipher: &C) -> Result<Self, Error<E>>
    where
        R: futures::io::AsyncRead + Unpin,
        C: Cipher,
    {
        use futures::io::AsyncReadExt;

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await?;

        let len = u32::from_be_bytes(buf);
        let size = buf.len() + len as usize + cipher.size();

        let mut buf = buf.to_vec();
        buf.resize(size, 0);

        reader.read_exact(&mut buf[..]).await?;

        Ok(Self::read_args(
            &mut std::io::Cursor::new(buf),
            (cipher.size(),),
        )?)
    }

    /// Write the [`Packet`] to the provided `writer`.
    pub fn to_writer<W, E>(&self, writer: &mut W) -> Result<(), Error<E>>
    where
        W: std::io::Write + std::io::Seek,
    {
        Ok(self.write(writer)?)
    }

    /// Write the [`Packet`] to the provided asynchronous `writer`.
    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    pub async fn to_async_writer<W, E>(&self, writer: &mut W) -> Result<(), Error<E>>
    where
        W: futures::io::AsyncWrite + Unpin,
    {
        use futures::io::AsyncWriteExt;

        let size = 4 + self.payload.len() + self.padding.len() + self.mac.len();

        let mut buf = std::io::Cursor::new(vec![0u8; size]);
        self.write(&mut buf)?;

        Ok(writer.write_all(&buf.into_inner()).await?)
    }
}

/// The cipher implemented to `decrypt` data from a [`Packet`]
/// or `encrypt` data to [`Packet`].
pub trait Cipher {
    /// The associated error which can be returned when encrypting or decrypting.
    type Err;

    /// The size of the Message Authentication Code for this [`Cipher`], in bytes.
    fn size(&self) -> usize;

    /// Transform the [`Packet`] using the [`Cipher`] into it's decrypted `payload`.
    fn decrypt(&mut self, packet: Packet) -> Result<Vec<u8>, Self::Err>;

    /// Transform the `payload` into it's encrypted [`Packet`] using the [`Cipher`].
    fn encrypt(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_cipher_is_object_safe() {
        struct Dummy;

        impl Cipher for Dummy {
            type Err = ();

            fn size(&self) -> usize {
                16
            }

            fn decrypt(&mut self, _packet: Packet) -> Result<Vec<u8>, Self::Err> {
                todo!()
            }

            fn encrypt(&mut self, _payload: Vec<u8>) -> Result<Packet, Self::Err> {
                todo!()
            }
        }

        let _: &dyn Cipher<Err = ()> = &Dummy;
    }
}
