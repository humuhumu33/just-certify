//! v0.4.0 T6 — lock in the invariant that opaque-bytes payloads
//! (PDFs, images, model weights) still produce a cert block whose
//! `?as=vc` projection is a valid, verifiable VC.
//!
//! The cryptosuite is agnostic to the data-block codec. The cert
//! block is always DAG-CBOR; its VC projection always verifies
//! through the same algorithm regardless of whether the referenced
//! `data_cid` is dag-cbor (`bafyrei…`) or raw (`bafkrei…`).
//!
//! Both tests are `#[ignore]`'d behind `SEM_IPLD_INTEGRATION=1`;
//! they need a running Kubo-backed service on localhost:8787.
//!
//! ```sh
//! ipfs daemon
//! SEM_IPLD_STORE=kubo cargo run --release --bin sem-ipld-service
//! SEM_IPLD_INTEGRATION=1 cargo test --release --test vc_projection -- --ignored
//! ```

use serde_json::Value;

const SERVICE: &str = "http://127.0.0.1:8787";

fn http_post(path: &str, content_type: &str, body: &[u8]) -> Value {
    let url = format!("{SERVICE}{path}");
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            &format!("Content-Type: {content_type}"),
            "--data-binary",
            "@-",
            &url,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.as_mut().unwrap().write_all(body).unwrap();
            c.wait_with_output()
        })
        .expect("curl");
    assert!(out.status.success(), "curl failed: {out:?}");
    serde_json::from_slice(&out.stdout).expect("JSON response")
}

fn http_get(url: &str) -> Value {
    let out = std::process::Command::new("curl")
        .args(["-sS", url])
        .output()
        .expect("curl");
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).expect("JSON response")
}

#[test]
#[ignore = "requires SEM_IPLD_INTEGRATION=1 and a running Kubo-backed service at 127.0.0.1:8787"]
fn opaque_bytes_cert_produces_verifiable_vc() {
    // 1. POST a binary payload (simulated PDF).
    let binary = b"%PDF-1.7 simulated pdf body";
    let resp = http_post("/v1/certify", "application/octet-stream", binary);
    let cert_cid = resp["certificate_cid"].as_str().unwrap();
    let data_cid = resp["data_cid"].as_str().unwrap();

    // The data CID uses the raw codec (starts with "bafkrei").
    assert!(data_cid.starts_with("bafkrei"), "got {data_cid}");
    // The cert CID is always dag-cbor (starts with "bafyrei").
    assert!(cert_cid.starts_with("bafyrei"), "got {cert_cid}");

    // 2. GET /v1/blocks/{cert_cid}?as=vc → 200 + VC.
    let vc = http_get(&format!("{SERVICE}/v1/blocks/{cert_cid}?as=vc"));

    // 3. Verify via the cryptosuite (unsigned path — no key resolver needed).
    uor_vc_crypto::verify(&vc, None).expect("VC from opaque-bytes cert must verify");

    // 4. credentialSubject.id is ipfs://<data_cid> using the raw codec.
    let subject_id = vc["credentialSubject"]["id"].as_str().unwrap();
    assert_eq!(subject_id, format!("ipfs://{data_cid}"));
    assert!(subject_id.contains("bafkrei"), "raw codec signal missing");

    // 5. Tamper with credentialSubject.id; verification must fail.
    let mut tampered = vc.clone();
    tampered["credentialSubject"]["id"] =
        Value::String(format!("ipfs://bafyreia2der{}", "a".repeat(49)));
    let err = uor_vc_crypto::verify(&tampered, None).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ProofMismatch") || msg.contains("SignatureInvalid"),
        "unexpected error: {msg}"
    );
}

#[test]
#[ignore = "requires SEM_IPLD_INTEGRATION=1 and running service"]
fn json_cert_and_bytes_cert_verify_identically() {
    // Prove: the cryptosuite does not care what codec the data block
    // uses; the cert block is DAG-CBOR in both cases and verifies via
    // the same algorithm.

    let json_resp = http_post(
        "/v1/certify",
        "application/json",
        br#"{"nonce":"json-mode"}"#,
    );
    let bytes_resp = http_post(
        "/v1/certify",
        "application/octet-stream",
        b"nonce-bytes-mode",
    );

    let json_cert = json_resp["certificate_cid"].as_str().unwrap();
    let bytes_cert = bytes_resp["certificate_cid"].as_str().unwrap();

    // Both cert CIDs use the dag-cbor codec.
    assert!(json_cert.starts_with("bafyrei"));
    assert!(bytes_cert.starts_with("bafyrei"));

    // Both VCs verify via the same algorithm.
    let json_vc = http_get(&format!("{SERVICE}/v1/blocks/{json_cert}?as=vc"));
    let bytes_vc = http_get(&format!("{SERVICE}/v1/blocks/{bytes_cert}?as=vc"));
    uor_vc_crypto::verify(&json_vc, None).expect("JSON-cert VC verifies");
    uor_vc_crypto::verify(&bytes_vc, None).expect("bytes-cert VC verifies");

    // And the two cert CIDs differ (different payload → different cert).
    assert_ne!(json_cert, bytes_cert);
}
