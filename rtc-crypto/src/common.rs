use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    SecretVec, StreamCipher, StreamCipherAlgorithm,
};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInPlace;
use ccm::consts::{U8, U12, U16};
use ctr::cipher::StreamCipher as CtrStreamCipher;
use md5::{Digest, Md5};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

// SRTP counter mode (RFC 3711 section 4.1.1) is AES-CTR with a big-endian 128-bit counter.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Buffers an OS-seeded CSPRNG and reseeds after at most 64 KiB of output.
#[derive(Default)]
struct RandomBuffer {
    rng: Option<rand::rngs::StdRng>,
    generated: usize,
}

impl RandomBuffer {
    /// Fills output while propagating failures from the initial seed or a later reseed.
    fn fill(
        &mut self,
        output: &mut [u8],
        mut seed: impl FnMut() -> Result<rand::rngs::StdRng, CryptoError>,
    ) -> Result<(), CryptoError> {
        use rand::Rng;
        const RESEED_AFTER: usize = 64 * 1024;
        for chunk in output.chunks_mut(RESEED_AFTER) {
            if self.rng.is_none() || self.generated + chunk.len() > RESEED_AFTER {
                self.rng = Some(seed()?);
                self.generated = 0;
            }
            if let Some(rng) = &mut self.rng {
                rng.fill_bytes(chunk);
            }
            self.generated += chunk.len();
        }
        Ok(())
    }
}

thread_local! {
    static RANDOM: std::cell::RefCell<RandomBuffer> = std::cell::RefCell::default();
}

/// Fills output from a buffered CSPRNG with fallible OS seeding and reseeding.
pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    use rand::SeedableRng;
    RANDOM.with(|random| {
        random.borrow_mut().fill(output, || {
            rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)
                .map_err(|_| CryptoError::RandomnessFailed)
        })
    })
}

/// Verifies legacy RSA-SHA384 keys below the backends' 2048-bit lower bound.
pub(crate) fn verify_legacy_rsa_sha384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;
    use sha2::Digest;
    let key =
        rsa::RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| CryptoError::InvalidSignature)?;
    if !(1024..=8192).contains(&key.n().bits()) {
        return Err(CryptoError::InvalidSignature);
    }
    key.verify(
        rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
        &sha2::Sha384::digest(message),
        signature,
    )
    .map_err(|_| CryptoError::InvalidSignature)
}

pub(crate) fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

pub(crate) fn block_encrypt(
    algorithm: BlockCipherAlgorithm,
    key: &[u8],
    block: &mut [u8],
) -> Result<(), CryptoError> {
    check_len(AES_BLOCK_LEN, block.len(), LengthKind::Output)?;
    match algorithm {
        BlockCipherAlgorithm::Aes128 => {
            check_key_len(16, key.len())?;
            Aes128::new_from_slice(key)
                .map_err(|_| invalid_key(16, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
        BlockCipherAlgorithm::Aes256 => {
            check_key_len(32, key.len())?;
            Aes256::new_from_slice(key)
                .map_err(|_| invalid_key(32, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
    }
    Ok(())
}

pub(crate) fn new_stream_cipher(
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>, CryptoError> {
    let bits = match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => {
            check_key_len(16, key.len())?;
            AesKeyBits::Aes128
        }
        StreamCipherAlgorithm::Aes256Ctr => {
            check_key_len(32, key.len())?;
            AesKeyBits::Aes256
        }
    };
    Ok(Box::new(AesCtr {
        key: SecretVec::new(key.to_vec()),
        bits,
    }))
}

pub(crate) fn new_cbc(
    algorithm: CbcAlgorithm,
    key: &[u8],
) -> Result<Box<dyn CbcCipher>, CryptoError> {
    match algorithm {
        CbcAlgorithm::Aes256Cbc => Ok(Box::new(AesCbc {
            key: ExpandedAesKey::new_256(key)?,
        })),
    }
}

pub(crate) fn new_ccm(
    algorithm: AeadAlgorithm,
    key: &[u8],
) -> Result<Box<dyn AeadCipher>, CryptoError> {
    check_key_len(16, key.len())?;
    let cipher = match algorithm {
        AeadAlgorithm::Aes128Ccm => {
            CommonCcm::Full(Aes128Ccm::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?)
        }
        AeadAlgorithm::Aes128Ccm8 => CommonCcm::Short(
            Aes128Ccm8::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?,
        ),
        _ => {
            return Err(CryptoError::UnsupportedAlgorithm(
                crate::CryptoAlgorithm::Aead(algorithm),
            ));
        }
    };
    Ok(Box::new(cipher))
}

// Stores an expanded key inside an already boxed cipher object, avoiding another allocation in
// every constructed state object. Only AES-256 is needed: `CbcAlgorithm` has a single variant,
// and CTR now goes through the `ctr` crate.
#[allow(clippy::large_enum_variant)]
enum ExpandedAesKey {
    Aes256(Aes256),
}

impl ExpandedAesKey {
    fn new_256(key: &[u8]) -> Result<Self, CryptoError> {
        check_key_len(32, key.len())?;
        Ok(Self::Aes256(
            Aes256::new_from_slice(key).map_err(|_| invalid_key(32, key.len()))?,
        ))
    }

    fn encrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.decrypt_block(GenericArray::from_mut_slice(block)),
        }
    }
}

/// AES counter mode.
///
/// Delegates to the `ctr` crate rather than driving `encrypt_block` once per 16-byte block, which
/// defeats the batching that lets AES-NI / ARMv8 crypto instructions pipeline. Measured ~9-10%
/// faster on a 1200-byte SRTP payload and ~8-10% slower on a two-block RTCP packet, where the
/// per-call setup dominates; RTP traffic dominates in practice. See
/// `rtc-srtp/benches/README.md`.
///
/// The key is retained rather than pre-expanded because `ctr::Ctr128BE` owns its own cipher
/// state and is constructed per call. It is held in a [`SecretVec`] so it is zeroized on drop.
struct AesCtr {
    key: SecretVec,
    bits: AesKeyBits,
}

#[derive(Clone, Copy)]
enum AesKeyBits {
    Aes128,
    Aes256,
}

impl StreamCipher for AesCtr {
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        let nonce = GenericArray::from_slice(iv);
        let key = self.key.as_ref();
        match self.bits {
            AesKeyBits::Aes128 => {
                let mut stream = Aes128Ctr::new(GenericArray::from_slice(key), nonce);
                stream.apply_keystream(data);
            }
            AesKeyBits::Aes256 => {
                let mut stream = Aes256Ctr::new(GenericArray::from_slice(key), nonce);
                stream.apply_keystream(data);
            }
        }
        Ok(())
    }
}

struct AesCbc {
    key: ExpandedAesKey,
}

impl CbcCipher for AesCbc {
    fn block_len(&self) -> usize {
        AES_BLOCK_LEN
    }

    fn encrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        check_blocks(blocks)?;
        let mut previous: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        // `check_blocks` has already rejected a length that is not a whole number of blocks, so the
        // remainder this returns is empty and the array chunks are the whole input.
        for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            for (byte, prior) in block.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            self.key.encrypt(block);
            previous = *block;
        }
        Ok(())
    }

    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        check_blocks(blocks)?;
        let mut previous: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            // The ciphertext masks the *next* block, so it has to be kept before decryption
            // overwrites it in place.
            let ciphertext = *block;
            self.key.decrypt(block);
            for (byte, prior) in block.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            previous = ciphertext;
        }
        Ok(())
    }
}

enum CommonCcm {
    Full(Aes128Ccm),
    Short(Aes128Ccm8),
}

impl AeadCipher for CommonCcm {
    fn tag_len(&self) -> usize {
        match self {
            Self::Full(_) => 16,
            Self::Short(_) => 8,
        }
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
        check_tag_len(self.tag_len(), tag_out.len())?;
        match self {
            Self::Full(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        plaintext_and_ciphertext,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
            Self::Short(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        plaintext_and_ciphertext,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
        }
        Ok(())
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
        check_tag_len(self.tag_len(), tag.len())?;
        match self {
            Self::Full(cipher) => cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    aad,
                    ciphertext_and_plaintext,
                    GenericArray::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
            Self::Short(cipher) => cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    aad,
                    ciphertext_and_plaintext,
                    GenericArray::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }
}

fn check_blocks(blocks: &[u8]) -> Result<(), CryptoError> {
    if blocks.is_empty() || !blocks.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(CryptoError::OutputTooSmall {
            required: blocks
                .len()
                .next_multiple_of(AES_BLOCK_LEN)
                .max(AES_BLOCK_LEN),
            actual: blocks.len(),
        });
    }
    Ok(())
}

enum LengthKind {
    Output,
}

fn check_len(expected: usize, actual: usize, kind: LengthKind) -> Result<(), CryptoError> {
    if expected == actual {
        return Ok(());
    }
    match kind {
        LengthKind::Output => Err(CryptoError::OutputTooSmall {
            required: expected,
            actual,
        }),
    }
}

pub(crate) fn check_key_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_key(expected, actual))
    }
}

pub(crate) fn check_nonce_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_nonce(expected, actual))
    }
}

pub(crate) fn check_tag_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidTagLength { expected, actual })
    }
}

fn invalid_key(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidKeyLength { expected, actual }
}

fn invalid_nonce(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidNonceLength { expected, actual }
}

#[cfg(test)]
mod random_tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn randomness_failures_during_seed_and_reseed_return_errors() {
        let mut buffer = RandomBuffer::default();
        let mut output = [7; 16];
        assert!(matches!(
            buffer.fill(&mut output, || Err(CryptoError::RandomnessFailed)),
            Err(CryptoError::RandomnessFailed)
        ));
        assert_eq!(output, [7; 16]);
        buffer
            .fill(&mut output, || Ok(rand::rngs::StdRng::from_seed([1; 32])))
            .unwrap();
        buffer.generated = 64 * 1024;
        output.fill(7);
        assert!(matches!(
            buffer.fill(&mut output, || Err(CryptoError::RandomnessFailed)),
            Err(CryptoError::RandomnessFailed)
        ));
        assert_eq!(output, [7; 16]);
    }
}
