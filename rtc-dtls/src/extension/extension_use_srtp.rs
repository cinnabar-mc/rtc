#[cfg(test)]
mod extension_use_srtp_test;

use super::*;

// SRTPProtectionProfile defines the parameters and options that are in effect for the SRTP processing
/// ## Specifications
///
/// * [RFC 5764 §4.1.2]
///
/// [RFC 5764 §4.1.2]: https://tools.ietf.org/html/rfc5764#section-4.1.2
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtpProtectionProfile {
    /// `SRTP_AES128_CM_HMAC_SHA1_80` (`0x0001`).
    Srtp_Aes128_Cm_Hmac_Sha1_80 = 0x0001,
    /// `SRTP_AES128_CM_HMAC_SHA1_32` (`0x0002`).
    Srtp_Aes128_Cm_Hmac_Sha1_32 = 0x0002,
    /// `SRTP_AEAD_AES_128_GCM` (`0x0007`).
    Srtp_Aead_Aes_128_Gcm = 0x0007,
    /// `SRTP_AEAD_AES_256_GCM` (`0x0008`).
    Srtp_Aead_Aes_256_Gcm = 0x0008,
    /// A protection profile this crate does not implement.
    Unsupported,
}

impl From<u16> for SrtpProtectionProfile {
    fn from(val: u16) -> Self {
        match val {
            0x0001 => SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            0x0002 => SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
            0x0007 => SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            0x0008 => SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
            _ => SrtpProtectionProfile::Unsupported,
        }
    }
}

const EXTENSION_USE_SRTPHEADER_SIZE: usize = 6;

/// ## Specifications
///
/// * [RFC 8422]
///
/// [RFC 8422]: https://tools.ietf.org/html/rfc8422
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionUseSrtp {
    pub(crate) master_key_identifier: Vec<u8>,
    pub(crate) protection_profiles: Vec<SrtpProtectionProfile>,
}

impl ExtensionUseSrtp {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::UseSrtp
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.protection_profiles.len() * 2 + 1 + self.master_key_identifier.len()
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mki_len =
            u8::try_from(self.master_key_identifier.len()).map_err(|_| Error::ErrLengthMismatch)?;
        let length = u16::try_from(self.size() - 2).map_err(|_| Error::ErrLengthMismatch)?;
        let profiles = u16::try_from(
            self.protection_profiles
                .len()
                .checked_mul(2)
                .ok_or(Error::ErrLengthMismatch)?,
        )
        .map_err(|_| Error::ErrLengthMismatch)?;
        writer.write_u16::<BigEndian>(length)?;
        writer.write_u16::<BigEndian>(profiles)?;
        for v in &self.protection_profiles {
            writer.write_u16::<BigEndian>(*v as u16)?;
        }

        /* MKI Length */
        writer.write_u8(mki_len)?;
        writer.write_all(&self.master_key_identifier)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let length = reader.read_u16::<BigEndian>()? as usize;
        let mut payload = Vec::new();
        reader.take(length as u64).read_to_end(&mut payload)?;
        if payload.len() != length || length < 3 {
            return Err(Error::ErrLengthMismatch);
        }
        let mut remaining = payload.as_slice();
        let profile_bytes = remaining.read_u16::<BigEndian>()? as usize;
        if profile_bytes == 0
            || !profile_bytes.is_multiple_of(2)
            || profile_bytes >= remaining.len()
        {
            return Err(Error::ErrLengthMismatch);
        }
        let mut protection_profiles = Vec::new();
        for _ in 0..profile_bytes / 2 {
            protection_profiles.push(remaining.read_u16::<BigEndian>()?.into());
        }
        let mki_length = remaining.read_u8()? as usize;
        if mki_length != remaining.len() {
            return Err(Error::ErrLengthMismatch);
        }
        Ok(ExtensionUseSrtp {
            protection_profiles,
            master_key_identifier: remaining.to_vec(),
        })
    }
}
