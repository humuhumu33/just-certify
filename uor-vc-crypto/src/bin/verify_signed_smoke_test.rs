//! `verify_signed_smoke_test <vc-json>` — resolves the VC's
//! `proof.verificationMethod` by fetching the running service's
//! `/v1/health` endpoint, reads the `publicKeyMultibase` out of the
//! `signing` block, verifies the VC with the resolved key.
//!
//! The key resolution here is deliberately minimal — not a full DID
//! resolver. Production verifiers use `didkit` / `did-resolver`; the
//! smoke test uses the service's own health endpoint as its "oracle"
//! for the public key. That's enough to exercise the signed
//! cryptosuite end-to-end.

use std::process::ExitCode;

use uor_vc_crypto::{
    ed25519_public_from_multikey, verify, CryptoError, VerificationKeyResolver,
};

struct HealthEndpointResolver {
    service_url: String,
}

impl VerificationKeyResolver for HealthEndpointResolver {
    fn resolve(
        &self,
        _verification_method: &str,
    ) -> Result<ed25519_dalek::VerifyingKey, CryptoError> {
        let url = format!("{}/v1/health", self.service_url);
        let body: serde_json::Value = ureq_like_get(&url).map_err(|e| {
            CryptoError::UnresolvableVerificationMethod(format!(
                "health fetch failed: {e}"
            ))
        })?;
        let mk = body
            .get("signing")
            .and_then(|s| s.get("public_key_multibase"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CryptoError::UnresolvableVerificationMethod(
                    "health response missing signing.public_key_multibase"
                        .into(),
                )
            })?;
        ed25519_public_from_multikey(mk)
    }
}

/// Tiny blocking HTTP GET — we avoid taking a heavy HTTP client dep
/// in this test binary. Shells out to `curl` which is universally
/// available in the test environment.
fn ureq_like_get(url: &str) -> Result<serde_json::Value, String> {
    let output = std::process::Command::new("curl")
        .args(["-sS", url])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "curl exited non-zero: {:?}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("JSON parse: {e}"))
}

fn main() -> ExitCode {
    let vc_arg = match std::env::args().nth(1) {
        Some(s) => s,
        None => {
            eprintln!("usage: verify_signed_smoke_test <vc-json>");
            return ExitCode::from(2);
        }
    };
    let service_url = std::env::var("SEM_IPLD_SERVICE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".into());

    let vc: serde_json::Value = match serde_json::from_str(&vc_arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input is not valid JSON: {e}");
            return ExitCode::from(2);
        }
    };

    let resolver = HealthEndpointResolver { service_url };
    match verify(&vc, Some(&resolver)) {
        Ok(()) => {
            println!("VC verified (signed): Ok");
            ExitCode::from(0)
        }
        Err(e) => {
            println!("VC verification failed: {e:?}");
            ExitCode::from(1)
        }
    }
}
