//! Canonical round-trip — the example the revised vision asked for.
//!
//! Run:
//!
//! ```sh
//! cargo run --example round_trip --features publish
//! ```
//!
//! Demonstrates, in <90 lines of user code:
//!
//! 1. Pin the UOR OWL context to its own CID (one call).
//! 2. Publish a FOAF-style payload — emits the linked CID pair + SRI
//!    integrity attribute.
//! 3. Show that re-publishing the same payload with different UOR
//!    state produces the *same* `data_cid` and a *different*
//!    `certificate_cid` (the semantic-versioning-over-byte-immutability
//!    property).
//! 4. Reverse the JSON-LD projection via `load_as_jsonld`.

use sem_ipld::prelude::*;
use serde_json::json;
use uor_foundation::enforcement::ContentFingerprint;

const UOR_CONTEXT_BYTES: &[u8] =
    br#"{"@context":{"u":"https://uor.foundation/","xsd":"http://www.w3.org/2001/XMLSchema#"}}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Pin the UOR OWL context to its own CID.
    let context =
        SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, UOR_CONTEXT_BYTES)?;
    println!("context IRI : {}", context.iri);
    println!("context CID : {}", context.cid);

    // 2. A tiny FOAF knowledge-graph fragment.
    let payload = json!({
        "@type": "foaf:Person",
        "foaf:name": "Ada Lovelace",
        "u:knows": [
            { "foaf:name": "Charles Babbage" },
            { "foaf:name": "Augusta De Morgan" }
        ]
    });

    // 3. Publish using the lower-level `publish_parts` — in production
    //    the UOR primitives come from a real `Grounded<T>` via
    //    `publish_semantic(&grounded, …)`. Here we inline the values
    //    so the example stays self-contained.
    let block = publish_parts(
        &context,
        &payload,
        /* witt_bits       */ 8,
        /* witt_level_bits */ 3,
        /* unit_address    */ 0xdead_beef,
        ContentFingerprint::from_buffer([0x2a; 32], 32),
    )?;

    println!("\n--- published block pair ---");
    println!("data CID        : {}", block.data_cid);
    println!("certificate CID : {}", block.certificate_cid);
    println!("data bytes      : {}", block.data_bytes.len());
    println!("cert bytes      : {}", block.certificate_bytes.len());
    println!("<link integrity=\"{}\">", block.integrity_attr);

    // 4. Same payload, different UOR state → same data CID.
    let block2 = publish_parts(
        &context,
        &payload,
        16,
        7,
        0xcafe,
        ContentFingerprint::from_buffer([0x55; 32], 32),
    )?;
    assert_eq!(block.data_cid, block2.data_cid);
    assert_ne!(block.certificate_cid, block2.certificate_cid);
    println!(
        "\n✓ same payload, different constraints → same data CID, different cert CID"
    );

    // 5. Reverse the JSON-LD projection.
    let projected = json!({
        "@context": [context.iri, { "u": context.iri }],
        "@type": "u:Grounded",
        "u:contextCid": context.cid.to_string(),
        "u:payload": payload,
    });
    let loaded = load_as_jsonld(&projected)?;
    println!("\n--- load_as_jsonld ---");
    println!("context IRI : {}", loaded.context_iri);
    println!("context CID : {:?}", loaded.context_cid);
    println!(
        "✓ round-trip preserves context IRI and payload: {}",
        loaded.payload == projected["u:payload"]
    );

    Ok(())
}
