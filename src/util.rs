use sha2::{Digest, Sha256};
use uuid::Uuid;

/// `sha256:<hex>` digest of a string, used for `source_hash` and fingerprints.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Encode a UUID (16 bytes) as a left-zero-padded `bytes32` hex string, matching
/// the on-chain `pay(bytes32 scanId)` encoding (Section 21). Decode = low 16 bytes.
pub fn uuid_to_bytes32(id: Uuid) -> String {
    let mut buf = [0u8; 32];
    buf[16..].copy_from_slice(id.as_bytes());
    format!("0x{}", hex::encode(buf))
}
