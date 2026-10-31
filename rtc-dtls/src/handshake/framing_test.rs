use super::*;
use crate::compression_methods::{CompressionMethodId, CompressionMethods};

/// Builds a minimal hello body, optionally followed by an extensions vector.
fn hello(client: bool, tail: &[u8]) -> Vec<u8> {
    let mut body = vec![0xfe, 0xfd];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    if client {
        body.extend_from_slice(&[0, 0, 2, 0xc0, 0x2b, 1, 0]);
    } else {
        body.extend_from_slice(&[0xc0, 0x2b, 0]);
    }
    body.extend_from_slice(tail);
    body
}

#[test]
fn framing_hello_extensions() {
    for client in [false, true] {
        let decode = |tail: &[u8]| {
            let raw = hello(client, tail);
            if client {
                HandshakeMessageClientHello::unmarshal(&mut raw.as_slice())
                    .map(|h| h.extensions.len())
            } else {
                HandshakeMessageServerHello::unmarshal(&mut raw.as_slice())
                    .map(|h| h.extensions.len())
            }
        };
        assert_eq!(decode(&[]).unwrap(), 0);
        assert_eq!(decode(&[0, 0]).unwrap(), 0);
        assert!(decode(&[0]).is_err());
        assert_eq!(decode(&[0, 5, 0xfa, 0xfa, 0, 1, 7]).unwrap(), 0);
        assert!(decode(&[0, 4, 0xfa, 0xfa, 0, 1]).is_err());
        assert!(decode(&[0, 6, 0, 11, 0, 2, 2, 0]).is_err());
    }
}

#[test]
fn framing_client_session_id() {
    let original = hello(true, &[0, 0]);
    let expected = HandshakeMessageClientHello::unmarshal(&mut original.as_slice()).unwrap();
    let mut session = original;
    session[34] = 3;
    session.splice(35..35, [0, 1, 2]);
    assert_eq!(
        HandshakeMessageClientHello::unmarshal(&mut session.as_slice()).unwrap(),
        expected
    );
}

#[test]
fn framing_final_fields() {
    assert!(
        HandshakeMessageHelloVerifyRequest::unmarshal(&mut [0xfe, 0xfd, 1, 0xaa].as_slice())
            .is_ok()
    );
    for mut raw in [&[0xfe, 0xfd, 1][..], &[0xfe, 0xfd, 1, 0xaa, 0xbb]] {
        assert!(HandshakeMessageHelloVerifyRequest::unmarshal(&mut raw).is_err());
    }
    let raw = [3, 0, 23, 1, 7, 4, 3, 0, 1, 9];
    assert!(HandshakeMessageServerKeyExchange::unmarshal(&mut raw.as_slice()).is_ok());
    let mut extra = raw.to_vec();
    extra.push(0);
    assert!(HandshakeMessageServerKeyExchange::unmarshal(&mut extra.as_slice()).is_err());
}

#[test]
fn framing_certificate_authorities() {
    for mut raw in [
        &[1, 1, 0, 2, 4, 1][..],
        &[1, 1, 0, 1, 4, 0, 0],
        &[1, 1, 0, 0, 0, 3, 0, 2, 1],
    ] {
        assert!(HandshakeMessageCertificateRequest::unmarshal(&mut raw).is_err());
    }
    for mut raw in [&[1, 1, 0, 2, 4, 1, 0, 0][..], &[1, 1, 0, 0, 0, 3, 0, 1, 7]] {
        assert!(HandshakeMessageCertificateRequest::unmarshal(&mut raw).is_ok());
    }
}

#[test]
fn framing_compression_count() {
    let mut raw = vec![];
    let mut methods = CompressionMethods {
        ids: vec![CompressionMethodId::Null; 255],
    };
    methods.marshal(&mut raw).unwrap();
    assert_eq!(
        CompressionMethods::unmarshal(&mut raw.as_slice()).unwrap(),
        methods
    );
    methods.ids.push(CompressionMethodId::Null);
    raw.clear();
    assert!(methods.marshal(&mut raw).is_err());
    assert!(raw.is_empty());
}
