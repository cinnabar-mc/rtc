#[cfg(test)]
mod extension_supported_elliptic_curves_test;

use super::*;
use crate::curve::named_curve::*;

const EXTENSION_SUPPORTED_GROUPS_HEADER_SIZE: usize = 6;

/// ## Specifications
///
/// * [RFC 8422 §5.1.1]
///
/// [RFC 8422 §5.1.1]: https://tools.ietf.org/html/rfc8422#section-5.1.1
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionSupportedEllipticCurves {
    /// The curves the sender accepts, in preference order.
    pub elliptic_curves: Vec<NamedCurve>,
}

impl ExtensionSupportedEllipticCurves {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::SupportedEllipticCurves
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.elliptic_curves.len() * 2
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = u16::try_from(
            self.elliptic_curves
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or(Error::ErrLengthMismatch)?,
        )
        .map_err(|_| Error::ErrLengthMismatch)?;
        writer.write_u16::<BigEndian>(length)?;
        writer.write_u16::<BigEndian>(length - 2)?;
        for v in &self.elliptic_curves {
            writer.write_u16::<BigEndian>(*v as u16)?;
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
        let group_count = bytes / 2;
        let mut elliptic_curves = vec![];
        for _ in 0..group_count {
            let elliptic_curve = reader.read_u16::<BigEndian>()?.into();
            elliptic_curves.push(elliptic_curve);
        }

        Ok(ExtensionSupportedEllipticCurves { elliptic_curves })
    }
}
