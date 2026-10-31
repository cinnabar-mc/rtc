use super::*;

#[test]
fn framing_extension_lengths() {
    for mut raw in [
        &[0, 11, 0, 0, 1, 0][..],
        &[0, 10, 0, 3, 0, 1, 0xff],
        &[0, 13, 0, 3, 0, 1, 0xff],
        &[0, 23, 0, 1],
        &[0xff, 1, 0, 1, 1],
        &[0, 0, 0, 5, 0, 9, 0, 0, 0],
    ] {
        assert!(Extension::unmarshal(&mut raw).is_err(), "{raw:?}");
    }
}

#[test]
fn framing_empty_server_name_acknowledgment() {
    let raw = [0, 0, 0, 0, 0, 23, 0, 0];
    let mut reader = raw.as_slice();
    let ext = Extension::unmarshal(&mut reader).unwrap();
    assert_eq!(reader.len(), 4);
    let mut encoded = vec![];
    ext.marshal(&mut encoded).unwrap();
    assert_eq!(encoded, raw[..4]);
    assert!(Extension::unmarshal(&mut reader).is_ok());
    assert!(reader.is_empty());
}

#[test]
fn framing_extension_write_limits() {
    use crate::curve::named_curve::NamedCurve;
    use crate::signature_hash_algorithm::{
        HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm,
    };
    let extensions = [
        Extension::SupportedEllipticCurves(ExtensionSupportedEllipticCurves {
            elliptic_curves: vec![NamedCurve::P256; 32767],
        }),
        Extension::SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms: vec![
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa
                };
                32767
            ],
        }),
        Extension::SupportedPointFormats(ExtensionSupportedPointFormats {
            point_formats: vec![0; 256],
        }),
        Extension::ServerName(ExtensionServerName {
            server_name: "x".repeat(65531),
        }),
        Extension::UseSrtp(ExtensionUseSrtp {
            protection_profiles: vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80; 32767],
            master_key_identifier: vec![0],
        }),
    ];
    for mut extension in extensions {
        assert!(extension.marshal(&mut vec![]).is_err());
        match &mut extension {
            Extension::SupportedEllipticCurves(value) => {
                value.elliptic_curves.pop();
            }
            Extension::SupportedSignatureAlgorithms(value) => {
                value.signature_hash_algorithms.pop();
            }
            Extension::SupportedPointFormats(value) => {
                value.point_formats.pop();
            }
            Extension::ServerName(value) => {
                value.server_name.pop();
            }
            Extension::UseSrtp(value) => {
                value.protection_profiles.pop();
                value.master_key_identifier.clear();
            }
            _ => unreachable!(),
        }
        let mut raw = vec![];
        extension.marshal(&mut raw).unwrap();
        assert_eq!(
            Extension::unmarshal(&mut raw.as_slice()).unwrap(),
            extension
        );
    }
}
