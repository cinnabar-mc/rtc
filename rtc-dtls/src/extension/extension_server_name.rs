#[cfg(test)]
mod extension_server_name_test;

use super::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

const EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME: u8 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
/// The Server Name Indication extension, naming the host the client meant to reach.
pub struct ExtensionServerName {
    pub(crate) server_name: String,
}

impl ExtensionServerName {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::ServerName
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        if self.server_name.is_empty() {
            2
        } else {
            7 + self.server_name.len()
        }
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.server_name.is_empty() {
            writer.write_u16::<BigEndian>(0)?;
            return Ok(());
        }
        let length = u16::try_from(
            self.server_name
                .len()
                .checked_add(5)
                .ok_or(Error::ErrLengthMismatch)?,
        )
        .map_err(|_| Error::ErrLengthMismatch)?;
        writer.write_u16::<BigEndian>(length)?;
        writer.write_u16::<BigEndian>(length - 2)?;
        writer.write_u8(EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME)?;
        writer.write_u16::<BigEndian>(self.server_name.len() as u16)?;
        writer.write_all(self.server_name.as_bytes())?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let payload = read_payload(reader)?;
        if payload.is_empty() {
            return Ok(Self {
                server_name: String::new(),
            });
        }
        let reader = &mut payload.as_slice();
        let length = reader.read_u16::<BigEndian>()? as usize;
        if length != reader.len() {
            return Err(Error::ErrLengthMismatch);
        }

        let name_type = reader.read_u8()?;
        if name_type != EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME {
            return Err(Error::ErrInvalidSniFormat);
        }

        let buf_len = reader.read_u16::<BigEndian>()? as usize;
        if buf_len == 0 || buf_len != reader.len() {
            return Err(Error::ErrLengthMismatch);
        }
        let mut buf: Vec<u8> = vec![0u8; buf_len];
        reader.read_exact(&mut buf)?;

        let server_name = String::from_utf8(buf)?;

        Ok(ExtensionServerName { server_name })
    }
}
