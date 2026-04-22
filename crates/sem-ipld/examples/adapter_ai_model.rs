//! AI adapter — one-file pattern for fingerprinting a model artifact.
//!
//! A model is defined here as opaque weight bytes plus a serializable
//! metadata card (architecture, training budget, eval scores, …).
//! The adapter produces a `SemanticBlock` whose `data_cid` is stable
//! across re-trains that produce the same weights — and identical to
//! the fingerprint a Web2 JSON API would compute for the same metadata.
//!
//! Run:
//!
//! ```sh
//! cargo run --example adapter_ai_model --features publish
//! ```

use sem_ipld::prelude::*;
use serde::Serialize;
use serde_json::json;
use uor_foundation::enforcement::ContentFingerprint;

const UOR_CONTEXT_BYTES: &[u8] = br#"{"@context":{"u":"https://uor.foundation/"}}"#;

/// The model card — anything `Serialize`, folded over as DAG-CBOR.
#[derive(Serialize)]
struct ModelCard<'a> {
    name: &'a str,
    architecture: &'a str,
    training_tokens: u64,
    weights_sha256: [u8; 32], // sha256 of the raw weight bytes, attached
    evals: serde_json::Value,
}

fn ground_model_artifact(
    weights: &[u8],
    name: &str,
    architecture: &str,
    training_tokens: u64,
    evals: serde_json::Value,
) -> Result<SemanticBlock, Box<dyn std::error::Error>> {
    let context = SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, UOR_CONTEXT_BYTES)?;

    let card = ModelCard {
        name,
        architecture,
        training_tokens,
        weights_sha256: sha256(weights),
        evals,
    };

    // Publish through the standard composition. In production the
    // UOR primitives (witt_bits, fingerprint, …) come out of the
    // kernel's `pipeline::run_*`; for the example we inline placeholders.
    Ok(publish_parts(
        &context,
        &card,
        /* witt_bits       */ 16,
        /* witt_level_bits */ 4,
        /* unit_address    */ 0x2026_0422,
        ContentFingerprint::from_buffer(sha256(weights), 32),
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pretend-weights and a model card.
    let weights = b"<placeholder 1.2 GB weight tensor>";
    let block = ground_model_artifact(
        weights,
        "ada-small",
        "transformer",
        42_000_000_000,
        json!({ "mmlu": 0.62, "humaneval": 0.41 }),
    )?;

    println!("model data CID  : {}", block.data_cid);
    println!("certificate CID : {}", block.certificate_cid);
    println!("<link integrity=\"{}\">", block.integrity_attr);
    println!("\nAny IPFS gateway, Solid POD, Web2 model registry, or");
    println!("agent ecosystem can now fetch, verify, and reason over");
    println!("this artifact by CID — same fingerprint everywhere.");
    Ok(())
}
