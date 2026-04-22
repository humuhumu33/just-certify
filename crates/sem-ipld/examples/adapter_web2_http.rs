//! Web2 adapter — drop-in fingerprinting for any HTTP JSON API.
//!
//! The existing Web2 service keeps speaking HTTP + JSON exactly as it
//! always has. This ~40-line adapter canonicalizes the JSON response
//! via DAG-CBOR (deterministic by construction), computes the UOR
//! fingerprint, and emits three HTTP headers the client or any
//! downstream system can verify without speaking UOR at all.
//!
//! Run:
//!
//! ```sh
//! cargo run --example adapter_web2_http --features publish
//! ```

use sem_ipld::prelude::*;
use serde_json::json;

/// The one function Web2 code needs. Takes any serde-serializable
/// response body, returns `(body_bytes, http_headers)`.
fn uor_for_http<T: serde::Serialize>(
    response: &T,
) -> Result<(Vec<u8>, Vec<(&'static str, String)>), Box<dyn std::error::Error>> {
    // The canonical bytes are the same ones an IPLD peer or an AI
    // artifact would compute. Identity is shared across ecosystems.
    let (cbor_bytes, data_cid) = dag_cbor_encode(response)?;
    let integrity = sha256_integrity_attribute(&cbor_bytes);

    let headers = vec![
        (
            "X-UOR-Fingerprint",
            data_cid
                .hash()
                .digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        ),
        ("X-UOR-Data-CID", data_cid.to_string()),
        ("Integrity", integrity),
    ];

    // In a real service the caller serializes the response as JSON for
    // the wire. For the demo we return the CBOR bytes — swap in
    // `serde_json::to_vec(response)` for an actual HTTP body.
    Ok((cbor_bytes, headers))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A perfectly ordinary JSON API response.
    let response = json!({
        "user": "ada@uor.foundation",
        "orders": [ { "id": 42, "total_cents": 1999 } ],
        "timestamp": 1713789600
    });

    let (_body, headers) = uor_for_http(&response)?;

    println!("--- outgoing HTTP response headers ---");
    for (k, v) in &headers {
        println!("{k}: {v}");
    }

    println!("\nThe response body speaks plain JSON. The headers carry");
    println!("a fingerprint that any IPFS node, Solid POD, or AI agent");
    println!("can verify identically — same canonical bytes underneath.");
    Ok(())
}
