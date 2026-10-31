use crypto::{CryptoAlgorithm, CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom};
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::config::ConfigBuilder;
use std::sync::Arc;

struct PskProvider;
impl RTCCryptoProvider for PskProvider {
    /// Names the test provider.
    fn name(&self) -> &'static str {
        "custom-psk"
    }
    /// Returns the test primitive capabilities.
    fn crypto(&self) -> &dyn RTCCrypto {
        self
    }
    /// Returns the test random source.
    fn random(&self) -> &dyn RTCRandom {
        self
    }
}
impl RTCCrypto for PskProvider {
    /// Advertises only the primitives needed to configure a PSK suite.
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        matches!(
            algorithm,
            CryptoAlgorithm::Hash(crypto::HashAlgorithm::Sha256)
                | CryptoAlgorithm::Hmac(crypto::HmacAlgorithm::Sha256)
                | CryptoAlgorithm::Aead(crypto::AeadAlgorithm::Aes128Ccm8)
        )
    }
}
impl RTCRandom for PskProvider {
    /// Rejects runtime entropy requests because this test only builds configurations.
    fn fill(&self, _output: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::RandomnessFailed)
    }
}

#[test]
fn custom_psk_configs_need_no_certificate_backend() {
    for client in [true, false] {
        assert!(
            ConfigBuilder::default()
                .with_crypto_provider(Arc::new(PskProvider))
                .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8])
                .with_psk(Some(Arc::new(|_| Ok(vec![7; 16]))))
                .with_psk_identity_hint(Some(b"peer".to_vec()))
                .build(client, None)
                .is_ok()
        );
    }
}
