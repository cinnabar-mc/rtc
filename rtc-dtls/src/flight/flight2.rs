use super::flight0::*;
use super::flight4::*;
use super::*;
use crate::content::*;
use crate::handshake::handshake_message_hello_verify_request::*;
use crate::handshake::*;
use crate::record_layer::record_layer_header::*;
use shared::error::Error;

use crate::config::HandshakeConfig;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight2;

impl fmt::Display for Flight2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 2")
    }
}

impl Flight for Flight2 {
    fn has_retransmit(&self) -> bool {
        false
    }

    fn parse(
        &self,
        //tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        let (seq, msgs) = match cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::ClientHello,
                epoch: cfg.initial_epoch,
                is_client: true,
                optional: false,
            }],
        ) {
            // No valid message received. Keep reading
            Ok((seq, msgs)) => (seq, msgs),

            // Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
            // Parse as flight 0 in this case.
            Err(_) => return Err((None, None)),
        };

        if let Some(message) = msgs.get(&HandshakeType::ClientHello) {
            // Validate type
            let client_hello = match message {
                HandshakeMessage::ClientHello(client_hello) => client_hello,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };

            if client_hello.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            if client_hello.cookie.is_empty() {
                return Err((None, None));
            }

            if state.cookie != client_hello.cookie {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::AccessDenied,
                    }),
                    Some(Error::ErrCookieMismatch),
                ));
            }

            if !cache.client_hello_core_matches(cfg.initial_epoch) {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::IllegalParameter,
                    }),
                    Some(Error::Other(
                        "ClientHello core parameters changed after cookie challenge".into(),
                    )),
                ));
            }
            negotiate_client_hello(state, cfg, client_hello)?;
            state.handshake_recv_sequence = seq;
            Ok(Box::new(Flight4 {}))
        } else {
            Err((
                Some(Alert {
                    alert_level: AlertLevel::Fatal,
                    alert_description: AlertDescription::InternalError,
                }),
                None,
            ))
        }
    }

    fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        _cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        state.handshake_send_sequence = 0;
        Ok(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(HandshakeMessage::HelloVerifyRequest(
                    HandshakeMessageHelloVerifyRequest {
                        version: PROTOCOL_VERSION1_2,
                        cookie: state.cookie.clone(),
                    },
                ))),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuiteId;
    use crate::compression_methods::{CompressionMethodId, CompressionMethods};
    use crate::curve::named_curve::NamedCurve;
    use crate::extension::{
        Extension, extension_supported_elliptic_curves::ExtensionSupportedEllipticCurves,
        extension_use_extended_master_secret::ExtensionUseExtendedMasterSecret,
    };
    use crate::handshake::{
        handshake_message_client_hello::HandshakeMessageClientHello,
        handshake_random::HandshakeRandom,
    };

    /// Creates a hello whose core parameters stay fixed across the cookie exchange.
    fn hello(curve: NamedCurve, ems: bool) -> HandshakeMessageClientHello {
        let mut extensions = vec![Extension::SupportedEllipticCurves(
            ExtensionSupportedEllipticCurves {
                elliptic_curves: vec![curve],
            },
        )];
        if ems {
            extensions.push(Extension::UseExtendedMasterSecret(
                ExtensionUseExtendedMasterSecret { supported: true },
            ));
        }
        HandshakeMessageClientHello {
            version: PROTOCOL_VERSION1_2,
            random: HandshakeRandom::default(),
            cookie: Vec::new(),
            cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            compression_methods: CompressionMethods {
                ids: vec![CompressionMethodId::Null],
            },
            extensions,
        }
    }

    /// Stores an encoded ClientHello at its original handshake sequence number.
    fn cache_hello(cache: &mut HandshakeCache, hello: HandshakeMessageClientHello, sequence: u16) {
        let mut handshake = Handshake::new(HandshakeMessage::ClientHello(hello));
        handshake.handshake_header.message_sequence = sequence;
        let mut raw = Vec::new();
        handshake.marshal(&mut raw).unwrap();
        assert!(cache.push(raw, 0, sequence, HandshakeType::ClientHello, true));
    }

    #[test]
    fn framing_disjoint_curves_fail_negotiation() {
        let provider = crypto::default_provider().unwrap();
        let mut cfg = HandshakeConfig::new(provider.clone());
        cfg.local_named_curves = vec![NamedCurve::P256];
        cfg.local_cipher_suites = vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256];
        assert!(
            negotiate_client_hello(
                &mut State::new(provider, false),
                &cfg,
                &hello(NamedCurve::X25519, false)
            )
            .is_err()
        );
    }

    #[test]
    fn cookie_hello_renegotiates_extensions_and_rejects_changed_core_parameters() {
        for change_core in [false, true] {
            let provider = crypto::default_provider().unwrap();
            let mut cfg = HandshakeConfig::new(provider.clone());
            cfg.local_named_curves = vec![NamedCurve::X25519, NamedCurve::P256];
            cfg.extended_master_secret = crate::config::ExtendedMasterSecretType::Request;
            cfg.local_cipher_suites = vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256];
            let mut state = State::new(provider, false);
            state.cookie = vec![7; 20];
            let mut cache = HandshakeCache::new();
            cache_hello(&mut cache, hello(NamedCurve::X25519, true), 0);
            Flight0.parse(&mut state, &cache, &cfg).unwrap();
            assert!(state.extended_master_secret);
            let mut retry = hello(NamedCurve::P256, false);
            retry.cookie = state.cookie.clone();
            if change_core {
                retry
                    .cipher_suites
                    .push(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha);
            }
            cache_hello(&mut cache, retry, 1);
            let result = Flight2.parse(&mut state, &cache, &cfg);
            if change_core {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().to_string(), "Flight 4");
                assert_eq!(state.named_curve, NamedCurve::P256);
                assert_eq!(
                    state.local_keypair.as_ref().unwrap().curve,
                    NamedCurve::P256
                );
                assert!(!state.extended_master_secret);
            }
        }
    }

    #[test]
    fn unrelated_handshake_input_does_not_retransmit_a_cookie_challenge() {
        let provider = crypto::default_provider().unwrap();
        let mut cfg = HandshakeConfig::new(provider.clone());
        cfg.local_named_curves = vec![NamedCurve::X25519];
        cfg.local_cipher_suites = vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256];
        let mut state = State::new(provider, false);
        let mut cache = HandshakeCache::new();
        cache_hello(&mut cache, hello(NamedCurve::X25519, false), 0);
        Flight0.parse(&mut state, &cache, &cfg).unwrap();
        assert!(matches!(
            Flight2.parse(&mut state, &cache, &cfg),
            Err((None, None))
        ));
    }

    #[test]
    fn cookie_retry_binds_unknown_cipher_codes_on_the_wire() {
        let provider = crypto::default_provider().unwrap();
        let mut cfg = HandshakeConfig::new(provider.clone());
        cfg.local_named_curves = vec![NamedCurve::X25519];
        cfg.local_cipher_suites = vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256];
        let mut state = State::new(provider, false);
        state.cookie = vec![7; 20];
        let mut cache = HandshakeCache::new();
        for sequence in 0..2u16 {
            let mut offered = hello(NamedCurve::X25519, false);
            offered.cipher_suites.push(CipherSuiteId::Unsupported);
            if sequence != 0 {
                offered.cookie = state.cookie.clone();
            }
            let mut handshake = Handshake::new(HandshakeMessage::ClientHello(offered));
            handshake.handshake_header.message_sequence = sequence;
            let mut raw = Vec::new();
            handshake.marshal(&mut raw).unwrap();
            let cookie_length = if sequence == 0 { 0 } else { state.cookie.len() };
            // DTLS header, version/random, empty session ID, cookie vector, suite length and first suite.
            let offset = 12 + 34 + 1 + 1 + cookie_length + 2 + 2;
            raw[offset..offset + 2].copy_from_slice(&(0xabcd + sequence).to_be_bytes());
            cache.push(raw, 0, sequence, HandshakeType::ClientHello, true);
            if sequence == 0 {
                Flight0.parse(&mut state, &cache, &cfg).unwrap();
            }
        }
        assert!(matches!(
            Flight2.parse(&mut state, &cache, &cfg),
            Err((
                Some(Alert {
                    alert_description: AlertDescription::IllegalParameter,
                    ..
                }),
                _
            ))
        ));
    }
}
