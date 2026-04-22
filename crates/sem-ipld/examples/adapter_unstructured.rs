//! Unstructured data adapter — fingerprint any opaque blob.
//!
//! The surveyed Anima ingestion pipeline supports PDF / DOCX / MD / TXT
//! / PNG / JPG / MP3 / WAV / video / code files. Every one of them
//! joins sem-ipld's common fingerprint layer through **one call**:
//! `publish_raw(&ctx, &bytes, …)`. The data block's payload is a
//! CBOR byte string; the CID is the usual CIDv1(dag-cbor, sha2-256)
//! over the envelope. No per-format adapter needed.
//!
//! What an Anima-like host does differently (and where sem-ipld wins):
//! Anima fingerprints by `md5(content[:1000] + filename)`, which is
//! neither canonical nor stable. sem-ipld fingerprints the *whole*
//! canonical byte sequence, so a re-serialized PDF (or the same image
//! re-saved by a different tool) that preserves bytes preserves
//! identity — and any change flips the CID cleanly.
//!
//! Run:
//!
//! ```sh
//! cargo run --example adapter_unstructured --features publish
//! ```

use sem_ipld::prelude::*;
use uor_foundation::enforcement::ContentFingerprint;

const UOR_CONTEXT_BYTES: &[u8] = br#"{"@context":{"u":"https://uor.foundation/"}}"#;

/// One helper that works for every unstructured blob: PDFs, images,
/// audio, model weights, tar archives — anything.
fn publish_blob(
    ctx: &SemanticContext,
    bytes: &[u8],
) -> Result<SemanticBlock, Box<dyn std::error::Error>> {
    // Real callers feed in the UOR primitives extracted from a
    // `Grounded<T>`. For a self-contained example we derive a
    // placeholder fingerprint directly from the blob.
    let fp_bytes: [u8; 32] = sha256(bytes);
    Ok(publish_raw(
        ctx,
        bytes,
        /* witt_bits       */ 8,
        /* witt_level_bits */ 3,
        /* unit_address    */ 0xdead_beef,
        ContentFingerprint::from_buffer(fp_bytes, 32),
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, UOR_CONTEXT_BYTES)?;

    // Four different "data types" — the adapter is the same function.
    let pdf_bytes = b"%PDF-1.7\n<<placeholder PDF body>>".as_slice();
    let png_bytes = &[
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, /* ... */
    ];
    let wav_bytes = b"RIFF\0\0\0\0WAVE".as_slice();
    let code_bytes = b"fn main() { println!(\"hello\") }".as_slice();

    for (label, bytes) in [
        ("PDF document ", pdf_bytes),
        ("PNG image    ", png_bytes),
        ("WAV audio    ", wav_bytes),
        ("Rust source  ", code_bytes),
    ] {
        let block = publish_blob(&ctx, bytes)?;
        println!("{label} → {}   {}", block.data_cid, block.integrity_attr);
    }

    println!(
        "\nEvery blob traveled through the same path — `publish_raw`.\n\
         The Anima-style hard-coded extension dispatch is gone; every\n\
         unstructured type joins the common identity layer identically."
    );
    Ok(())
}
