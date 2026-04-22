//! Multibase encoding helpers for W3C projection endpoints.
//!
//! Per Data Integrity 1.0, byte-typed fields in JSON-LD output are
//! multibase-encoded. We use Base58btc (`z` prefix) for general
//! byte fields (matching the convention in `Multikey` and existing
//! W3C cryptosuites) and Base64Url (`u` prefix) for multihash envelopes
//! carried as `digestMultibase`.

/// Base58btc multibase encoding — for `uor:fingerprint`, `uor:unitAddress`.
#[must_use]
pub fn encode_base58btc(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

/// Decode a multibase string into its bytes. The leading byte indicates
/// the alphabet; we accept any that `multibase::decode` supports.
///
/// # Errors
///
/// Returns [`multibase::Error`] if the string is not a valid multibase encoding.
pub fn decode_multibase(s: &str) -> Result<Vec<u8>, multibase::Error> {
    multibase::decode(s).map(|(_, bytes)| bytes)
}

/// Encode the raw 32-byte SHA-256 digest as a Base64Url multibase
/// multihash — the `digestMultibase` format specified by Data
/// Integrity 1.0 for referencing content-addressed blobs.
///
/// Layout: `multibase::Base64Url(multihash(0x12, 0x20, digest))`
///            prefix `u`       | \__ varint code + length + 32 bytes
#[must_use]
pub fn sha256_digest_multibase(digest: &[u8; 32]) -> String {
    // multihash header is two varint bytes for our case — the SHA-256
    // code (0x12) and length (0x20 = 32) each fit in a single byte.
    let mut wrapped = [0u8; 34];
    wrapped[0] = 0x12;
    wrapped[1] = 0x20;
    wrapped[2..].copy_from_slice(digest);
    multibase::encode(multibase::Base::Base64Url, wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58btc_round_trip() {
        let encoded = encode_base58btc(b"test");
        assert!(encoded.starts_with('z'), "got {encoded}");
        let decoded = decode_multibase(&encoded).unwrap();
        assert_eq!(decoded, b"test");
    }

    #[test]
    fn sha256_digest_multibase_shape() {
        let digest = [0u8; 32];
        let s = sha256_digest_multibase(&digest);
        assert!(s.starts_with('u'), "got {s}");
        // Decode back — should reveal 0x12 0x20 0x00…
        let raw = decode_multibase(&s).unwrap();
        assert_eq!(raw.len(), 34);
        assert_eq!(raw[0], 0x12);
        assert_eq!(raw[1], 0x20);
        assert_eq!(&raw[2..], &[0u8; 32]);
    }

    #[test]
    fn empty_input_is_valid() {
        let s = encode_base58btc(&[]);
        // `z` + nothing; decoding returns the empty slice.
        let back = decode_multibase(&s).unwrap();
        assert!(back.is_empty());
    }
}
