//! `verify_vc_smoke_test <vc-json-string>` — called by the v0.3.0
//! acceptance-gate script. Reads a VC JSON document from argv,
//! runs `uor_vc_crypto::verify`, prints the result, exits 0 on `Ok`
//! and 1 on any error.

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = match std::env::args().nth(1) {
        Some(s) => s,
        None => {
            eprintln!("usage: verify_vc_smoke_test <vc-json>");
            return ExitCode::from(2);
        }
    };

    let value: serde_json::Value = match serde_json::from_str(&arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input is not valid JSON: {e}");
            return ExitCode::from(2);
        }
    };

    // v0.4.0: the dispatcher takes an optional resolver. This binary
    // targets the unsigned cryptosuite and passes `None`; the signed
    // analog lives in `verify_signed_smoke_test`.
    match uor_vc_crypto::verify(&value, None) {
        Ok(()) => {
            println!("VC verified: Ok");
            ExitCode::from(0)
        }
        Err(e) => {
            println!("VC verification failed: {e}");
            ExitCode::from(1)
        }
    }
}
