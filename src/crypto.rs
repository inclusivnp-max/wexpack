//! Argon2id v0x13 + XChaCha20-Poly1305, exactly matching the v2 wire profile.
//! A sealer generates a fresh archive identity; reopening an identity only permits
//! decryption. Chunk IDs must increase and the index can be sealed only once.
//!
//! ```
//! use wexpack::crypto::{ArchiveSealer, ArchiveOpener, KdfParameters, CryptoLimits};
//! use wexpack::format::{CodecType, DecodeLimits, IndexEnvelope};
//! let mut writer = ArchiveSealer::new(b"a long example password", KdfParameters::default())?;
//! let envelope = IndexEnvelope {
//!     codec: CodecType::Store, encrypted: false, decoded_size: 64, payload_size: 64,
//! };
//! let (envelope, ciphertext) = writer.seal_index(envelope, &[0; 64], DecodeLimits::default())?;
//! let reader = ArchiveOpener::new(b"a long example password", *writer.descriptor(), CryptoLimits::default())?;
//! assert_eq!(reader.open_index(&envelope, &ciphertext, DecodeLimits::default())?.as_slice(), &[0; 64]);
//! # Ok::<(), wexpack::crypto::CryptoError>(())
//! ```
use crate::format::{
    ChunkFlags, ChunkHeader, CryptoDescriptor, DecodeLimits, FormatError, IndexEnvelope,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce};
use std::fmt;
use zeroize::Zeroizing;

pub const TAG_SIZE: usize = 16;
pub const MAX_PASSWORD_BYTES: usize = 1 << 20;
pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug)]
pub enum CryptoError {
    Format(FormatError),
    ResourceLimit(&'static str),
    Random(getrandom::Error),
    Kdf(argon2::Error),
    AuthenticationFailed,
    InvalidState(&'static str),
    AllocationFailed,
}
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(e) => write!(f, "crypto framing: {e}"),
            Self::ResourceLimit(s) => write!(f, "crypto resource limit: {s}"),
            Self::Random(e) => write!(f, "archive randomness failed: {e}"),
            Self::Kdf(e) => write!(f, "Argon2id failed: {e}"),
            Self::AuthenticationFailed => f.write_str("AEAD authentication failed"),
            Self::InvalidState(s) => write!(f, "invalid encryption state: {s}"),
            Self::AllocationFailed => f.write_str("crypto allocation failed"),
        }
    }
}
impl std::error::Error for CryptoError {}
impl From<FormatError> for CryptoError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KdfParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}
impl Default for KdfParameters {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            lanes: 1,
        }
    }
}

/// Reader-side budgets are checked before allocating the Argon2 workspace.
#[derive(Debug, Clone, Copy)]
pub struct CryptoLimits {
    pub max_memory_kib: u32,
    pub max_iterations: u32,
    pub max_lanes: u32,
    pub max_work_kib: u64,
    pub max_payload_bytes: usize,
}
impl Default for CryptoLimits {
    fn default() -> Self {
        Self {
            max_memory_kib: 262_144,
            max_iterations: 10,
            max_lanes: 8,
            max_work_kib: 1_048_576,
            max_payload_bytes: 256 << 20,
        }
    }
}
impl CryptoLimits {
    fn validate(&self, descriptor: &CryptoDescriptor, password: &[u8]) -> Result<()> {
        descriptor.validate()?;
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(CryptoError::ResourceLimit("password length"));
        }
        if descriptor.memory_kib > self.max_memory_kib
            || descriptor.iterations > self.max_iterations
            || descriptor.lanes > self.max_lanes
            || u64::from(descriptor.memory_kib) * u64::from(descriptor.iterations)
                > self.max_work_kib
        {
            return Err(CryptoError::ResourceLimit("KDF cost"));
        }
        Ok(())
    }
}

// No Clone/Debug implementation: secret state must not leak through diagnostics.
struct Keys {
    master: Zeroizing<[u8; 32]>,
    chunk: Zeroizing<[u8; 32]>,
    index: Zeroizing<[u8; 32]>,
}
impl Keys {
    fn derive(
        password: &[u8],
        descriptor: &CryptoDescriptor,
        limits: CryptoLimits,
    ) -> Result<Self> {
        limits.validate(descriptor, password)?;
        let params = Params::new(
            descriptor.memory_kib,
            descriptor.iterations,
            descriptor.lanes,
            Some(32),
        )
        .map_err(CryptoError::Kdf)?;
        let mut workspace = Zeroizing::new(Vec::new());
        workspace
            .try_reserve_exact(params.block_count())
            .map_err(|_| CryptoError::AllocationFailed)?;
        workspace.resize(params.block_count(), Block::default());
        let mut master = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(
                password,
                &descriptor.salt,
                &mut *master,
                &mut workspace[..],
            )
            .map_err(CryptoError::Kdf)?;
        drop(workspace);
        let mut material = Zeroizing::new([0u8; 48]);
        material[..32].copy_from_slice(&*master);
        material[32..].copy_from_slice(&descriptor.archive_id);
        let chunk = Zeroizing::new(blake3::derive_key("WexPack v2 chunk key", &*material));
        let index = Zeroizing::new(blake3::derive_key("WexPack v2 index key", &*material));
        Ok(Self {
            master,
            chunk,
            index,
        })
    }
    fn nonce(&self, descriptor: &CryptoDescriptor, domain: u8, id: u64) -> XNonce {
        let mut material = Zeroizing::new([0u8; 57]);
        material[..32].copy_from_slice(&*self.master);
        material[32..48].copy_from_slice(&descriptor.archive_id);
        material[48] = domain;
        material[49..].copy_from_slice(&id.to_le_bytes());
        let digest = Zeroizing::new(blake3::derive_key("WexPack v2 nonce", &*material));
        let mut nonce = [0; 24];
        nonce.copy_from_slice(&digest[..24]);
        nonce.into()
    }
    fn crypt(
        &self,
        descriptor: &CryptoDescriptor,
        domain: u8,
        id: u64,
        aad: &[u8],
        input: &[u8],
        encrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key = if domain == 0 {
            &self.chunk
        } else {
            &self.index
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&**key)
            .map_err(|_| CryptoError::InvalidState("key size"))?;
        let mut buffer = Zeroizing::new(Vec::new());
        let capacity = input
            .len()
            .checked_add(if encrypt { TAG_SIZE } else { 0 })
            .ok_or(CryptoError::ResourceLimit("payload size overflow"))?;
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| CryptoError::AllocationFailed)?;
        buffer.extend_from_slice(input);
        let nonce = self.nonce(descriptor, domain, id);
        if encrypt {
            cipher.encrypt_in_place(&nonce, aad, &mut *buffer)
        } else {
            cipher.decrypt_in_place(&nonce, aad, &mut *buffer)
        }
        .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(buffer)
    }
}
fn chunk_aad(descriptor: &CryptoDescriptor, header: &ChunkHeader) -> [u8; 163] {
    let mut aad = [0; 163];
    aad[..11].copy_from_slice(b"WXP2 chunk\0");
    aad[11..107].copy_from_slice(&descriptor.to_bytes()[..96]);
    aad[107..].copy_from_slice(&header.to_bytes()[..56]);
    aad
}
fn index_aad(descriptor: &CryptoDescriptor, header: &IndexEnvelope) -> [u8; 135] {
    let mut aad = [0; 135];
    aad[..11].copy_from_slice(b"WXP2 index\0");
    aad[11..107].copy_from_slice(&descriptor.to_bytes()[..96]);
    aad[107..].copy_from_slice(&header.to_bytes()[..28]);
    aad
}

/// Single-use archive writer. Repacking creates a new instance and fresh CSPRNG identity.
pub struct ArchiveSealer {
    descriptor: CryptoDescriptor,
    keys: Keys,
    limits: CryptoLimits,
    last_chunk: Option<u32>,
    index_sealed: bool,
}
impl ArchiveSealer {
    pub fn new(password: &[u8], parameters: KdfParameters) -> Result<Self> {
        Self::with_limits(password, parameters, CryptoLimits::default())
    }
    pub fn with_limits(
        password: &[u8],
        parameters: KdfParameters,
        limits: CryptoLimits,
    ) -> Result<Self> {
        let mut descriptor = CryptoDescriptor {
            memory_kib: parameters.memory_kib,
            iterations: parameters.iterations,
            lanes: parameters.lanes,
            salt: [0; 32],
            archive_id: [0; 16],
        };
        limits.validate(&descriptor, password)?;
        getrandom::fill(&mut descriptor.salt).map_err(CryptoError::Random)?;
        getrandom::fill(&mut descriptor.archive_id).map_err(CryptoError::Random)?;
        let keys = Keys::derive(password, &descriptor, limits)?;
        Ok(Self {
            descriptor,
            keys,
            limits,
            last_chunk: None,
            index_sealed: false,
        })
    }
    pub fn descriptor(&self) -> &CryptoDescriptor {
        &self.descriptor
    }

    /// Accepts the plaintext codec header and returns its finalized encrypted equivalent.
    /// IDs increase strictly; validation failures do not consume an ID, encryption attempts do.
    pub fn seal_chunk(
        &mut self,
        mut header: ChunkHeader,
        payload: &[u8],
    ) -> Result<(ChunkHeader, Vec<u8>)> {
        header.validate()?;
        if self.index_sealed
            || header.flags.contains(ChunkFlags::ENCRYPTED)
            || self
                .last_chunk
                .is_some_and(|id| id >= header.chunk_id.get())
        {
            return Err(CryptoError::InvalidState(
                "reused/out-of-order chunk or finalized index",
            ));
        }
        header.verify_stored_payload(payload)?;
        let size = payload
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(CryptoError::ResourceLimit("chunk size"))?;
        if size > self.limits.max_payload_bytes {
            return Err(CryptoError::ResourceLimit("chunk payload"));
        }
        header.compressed_size =
            u32::try_from(size).map_err(|_| CryptoError::ResourceLimit("chunk size"))?;
        header.flags.insert(ChunkFlags::ENCRYPTED);
        header.validate()?;
        self.last_chunk = Some(header.chunk_id.get());
        let mut ciphertext = self.keys.crypt(
            &self.descriptor,
            0,
            u64::from(header.chunk_id.get()),
            &chunk_aad(&self.descriptor, &header),
            payload,
            true,
        )?;
        header.crc32 = crc32fast::hash(&ciphertext);
        Ok((header, std::mem::take(&mut *ciphertext)))
    }
    /// Finalizes this writer; the encrypted directory contains all paths and references.
    pub fn seal_index(
        &mut self,
        mut envelope: IndexEnvelope,
        payload: &[u8],
        limits: DecodeLimits,
    ) -> Result<(IndexEnvelope, Vec<u8>)> {
        envelope.validate(limits)?;
        if self.index_sealed || envelope.encrypted {
            return Err(CryptoError::InvalidState(
                "index already encrypted/finalized",
            ));
        }
        if envelope.payload_size != payload.len() as u64 {
            return Err(CryptoError::InvalidState("index payload length"));
        }
        let size = payload
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(CryptoError::ResourceLimit("index size"))?;
        if size > self.limits.max_payload_bytes {
            return Err(CryptoError::ResourceLimit("index payload"));
        }
        envelope.encrypted = true;
        envelope.payload_size = size as u64;
        envelope.validate(limits)?;
        self.index_sealed = true;
        let mut ciphertext = self.keys.crypt(
            &self.descriptor,
            1,
            0,
            &index_aad(&self.descriptor, &envelope),
            payload,
            true,
        )?;
        Ok((envelope, std::mem::take(&mut *ciphertext)))
    }
}

/// Reusable random-access decryptor. No encryption entry points accept an old identity.
pub struct ArchiveOpener {
    descriptor: CryptoDescriptor,
    keys: Keys,
    limits: CryptoLimits,
}
impl ArchiveOpener {
    /// A successful KDF does not authenticate the password; the first AEAD open does.
    pub fn new(
        password: &[u8],
        descriptor: CryptoDescriptor,
        limits: CryptoLimits,
    ) -> Result<Self> {
        let keys = Keys::derive(password, &descriptor, limits)?;
        Ok(Self {
            descriptor,
            keys,
            limits,
        })
    }
    pub fn open_chunk(
        &self,
        header: &ChunkHeader,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        header.validate()?;
        if !header.flags.contains(ChunkFlags::ENCRYPTED) {
            return Err(CryptoError::InvalidState("plaintext chunk passed to AEAD"));
        }
        if ciphertext.len() > self.limits.max_payload_bytes {
            return Err(CryptoError::ResourceLimit("chunk payload"));
        }
        header.verify_stored_payload(ciphertext)?;
        self.keys.crypt(
            &self.descriptor,
            0,
            u64::from(header.chunk_id.get()),
            &chunk_aad(&self.descriptor, header),
            ciphertext,
            false,
        )
    }
    pub fn open_index(
        &self,
        envelope: &IndexEnvelope,
        ciphertext: &[u8],
        limits: DecodeLimits,
    ) -> Result<Zeroizing<Vec<u8>>> {
        envelope.validate(limits)?;
        if !envelope.encrypted || envelope.payload_size != ciphertext.len() as u64 {
            return Err(CryptoError::InvalidState("encrypted index framing"));
        }
        if ciphertext.len() > self.limits.max_payload_bytes {
            return Err(CryptoError::ResourceLimit("index payload"));
        }
        self.keys.crypt(
            &self.descriptor,
            1,
            0,
            &index_aad(&self.descriptor, envelope),
            ciphertext,
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ChunkId, CodecType, TransformType};
    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_libargon2_libsodium_and_blake3_vector() {
        // Generated with libargon2, libsodium, and the Python BLAKE3 binding.
        let descriptor = CryptoDescriptor {
            memory_kib: 8192,
            iterations: 1,
            lanes: 1,
            salt: std::array::from_fn(|i| i as u8),
            archive_id: std::array::from_fn(|i| (i + 16) as u8),
        };
        let keys = Keys::derive(
            b"WexPack stage 4 reference password",
            &descriptor,
            CryptoLimits::default(),
        )
        .unwrap();
        assert_eq!(
            keys.master.as_slice(),
            unhex("7448b87b06ce90599d5788ee07204379618d32b07edd8acf21444f1eb57ce208")
        );
        assert_eq!(
            keys.chunk.as_slice(),
            unhex("09fc78bbda00bb96a20065f185ab3e3cfa2f877d04845332f4edb8017ade715c")
        );
        assert_eq!(
            keys.nonce(&descriptor, 0, 7).as_slice(),
            unhex("78daf43c9267c544b70cc537d6c346fa9981bbd1ee67bc96")
        );
        let plaintext = b"WexPack encrypted reference payload!";
        let mut sealer = ArchiveSealer {
            descriptor,
            keys,
            limits: CryptoLimits::default(),
            last_chunk: None,
            index_sealed: false,
        };
        let header = ChunkHeader {
            chunk_id: ChunkId::new(7).unwrap(),
            uncompressed_size: plaintext.len() as u32,
            transformed_size: plaintext.len() as u32,
            compressed_size: plaintext.len() as u32,
            codec: CodecType::Store,
            transform: TransformType::None,
            flags: ChunkFlags::empty(),
            hash: *blake3::hash(plaintext).as_bytes(),
            crc32: crc32fast::hash(plaintext),
        };
        let (_, ciphertext) = sealer.seal_chunk(header, plaintext).unwrap();
        assert_eq!(
            ciphertext,
            unhex(
                "0b6529b869e62eb8d32ab0215983bef85fa0d69f5b7966fa3ad039857b6cfdd500d61e324a75f2fa549dfd1f3f9f1b2d7685da79"
            )
        );
    }
    #[test]
    fn nonce_domains_ids_and_archive_identity_are_separated() {
        let descriptor = CryptoDescriptor {
            memory_kib: 8192,
            iterations: 1,
            lanes: 1,
            salt: [1; 32],
            archive_id: [2; 16],
        };
        let keys = Keys::derive(b"password", &descriptor, CryptoLimits::default()).unwrap();
        let mut nonces = std::collections::HashSet::new();
        for id in [0, 1, u32::MAX as u64 - 1, u64::MAX] {
            for domain in [0, 1] {
                assert!(nonces.insert(keys.nonce(&descriptor, domain, id).to_vec()));
            }
        }
        let mut other = descriptor;
        other.archive_id[0] ^= 1;
        assert_ne!(keys.nonce(&descriptor, 0, 0), keys.nonce(&other, 0, 0));
        assert_ne!(keys.chunk.as_slice(), keys.index.as_slice());
    }
}
