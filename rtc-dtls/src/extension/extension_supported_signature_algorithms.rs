#[cfg(test)]
mod extension_supported_signature_algorithms_test;

use super::*;
use crate::signature_hash_algorithm::*;

const EXTENSION_SUPPORTED_SIGNATURE_ALGORITHMS_HEADER_SIZE: usize = 6;

/// ## Specifications
///
/// * [RFC 5246 §7.4.1.4.1]
///
/// [RFC 5246 §7.4.1.4.1]: https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionSupportedSignatureAlgorithms {
    pub(crate) signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
}

impl ExtensionSupportedSignatureAlgorithms {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::SupportedSignatureAlgorithms
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.signature_hash_algorithms.len() * 2
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = u16::try_from(
            self.signature_hash_algorithms
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or(Error::ErrLengthMismatch)?,
        )
        .map_err(|_| Error::ErrLengthMismatch)?;
        writer.write_u16::<BigEndian>(length)?;
        writer.write_u16::<BigEndian>(length - 2)?;
        for v in &self.signature_hash_algorithms {
            writer.write_u8(v.hash as u8)?;
            writer.write_u8(v.signature as u8)?;
        }

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let payload = read_payload(reader)?;
        let reader = &mut payload.as_slice();
        let bytes = reader.read_u16::<BigEndian>()? as usize;
        if bytes != reader.len() || !bytes.is_multiple_of(2) {
            return Err(Error::ErrLengthMismatch);
        }
        let algorithm_count = bytes / 2;
        let mut signature_hash_algorithms = vec![];
        for _ in 0..algorithm_count {
            let hash = reader.read_u8()?.into();
            let signature = reader.read_u8()?.into();
            signature_hash_algorithms.push(SignatureHashAlgorithm { hash, signature });
        }

        Ok(ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms,
        })
    }
}
