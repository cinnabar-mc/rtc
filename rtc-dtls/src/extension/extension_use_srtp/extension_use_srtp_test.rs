use super::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_extension_use_srtp() -> Result<()> {
    let raw_use_srtp = vec![0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00]; //0x00, 0x0e,
    let parsed_use_srtp = ExtensionUseSrtp {
        master_key_identifier: vec![],
        protection_profiles: vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_use_srtp.marshal(&mut writer)?;
    }

    assert_eq!(
        raw, raw_use_srtp,
        "extensionUseSRTP marshal: got {raw:?}, want {raw_use_srtp:?}"
    );

    let mut reader = BufReader::new(raw.as_slice());
    let new_use_srtp = ExtensionUseSrtp::unmarshal(&mut reader)?;

    assert_eq!(
        new_use_srtp, parsed_use_srtp,
        "extensionUseSRTP unmarshal: got {new_use_srtp:?}, want {parsed_use_srtp:?}"
    );

    Ok(())
}

#[test]
fn srtp_extension_checks_profile_and_mki_lengths() {
    for raw in [
        vec![0, 5, 0, 3, 0, 1, 0],
        vec![0, 5, 0, 2, 0, 1, 1],
        vec![0, 3, 0, 2, 0, 1, 0],
    ] {
        assert!(
            ExtensionUseSrtp::unmarshal(&mut raw.as_slice()).is_err(),
            "{raw:?}"
        );
    }
}

#[test]
fn srtp_mki_roundtrips_without_consuming_the_following_extension() {
    let raw = [0, 7, 0, 2, 0, 1, 2, 0xaa, 0xbb, 0xee];
    let mut reader = raw.as_slice();
    let extension = ExtensionUseSrtp::unmarshal(&mut reader).unwrap();
    assert_eq!(extension.master_key_identifier, [0xaa, 0xbb]);
    assert_eq!(reader, [0xee]);
    let mut encoded = Vec::new();
    extension.marshal(&mut encoded).unwrap();
    assert_eq!(encoded, raw[..9]);
}
