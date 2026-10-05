// Throwaway CLI for kyriakon-infra#185. The logic lives in src/lib.rs, which the browser
// page loads as WebAssembly, so this exists only to drive the same code from a shell and to
// write keys out for the client tests.
//
// Not the deliverable. No error handling worth the name, no CLI worth the name.

use keygen_spike::{check_public_key, generate_key, self_check, DEFAULT_USER_ID};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::packet::SubpacketData;
use pgp::types::KeyDetails;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--self-check") => {
            self_check()?;
            println!("self-check ok");
        }
        Some("dump") => {
            let raw = fs::read_to_string(args.get(2).cloned().unwrap())?;
            let (key, _) = SignedPublicKey::from_armor_single(raw.as_bytes())?;
            let mut sigs: Vec<(&str, &pgp::packet::Signature)> = Vec::new();
            for sig in &key.details.direct_signatures {
                sigs.push(("direct", sig));
            }
            for user in &key.details.users {
                for sig in &user.signatures {
                    sigs.push(("user", sig));
                }
            }
            for (where_, sig) in sigs {
                println!("{where_} signature, typ {:?}", sig.typ());
                if let Some(config) = sig.config() {
                    for subpacket in config.hashed_subpackets() {
                        println!("    {:?}", subpacket.data);
                    }
                }
            }
        }
        Some("check") => {
            let path = args.get(2).cloned().unwrap_or_else(|| "public.asc".into());
            let raw = fs::read_to_string(&path)?;
            let findings = check_public_key(&raw, now_secs())?;
            if findings.is_empty() {
                println!("OK   {path}");
            } else {
                println!("FAIL {path}");
                for finding in findings {
                    println!("     {finding}");
                }
            }
        }
        _ => {
            let variant = args.get(1).map(String::as_str).unwrap_or("ed25519");
            let out = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "/tmp/keygen-out".into());
            fs::create_dir_all(&out)?;
            let key = generate_key(
                variant,
                DEFAULT_USER_ID,
                Some("spike-passphrase-not-a-secret"),
            )?;
            fs::write(format!("{out}/secret.asc"), &key.secret_armor)?;
            fs::write(format!("{out}/public.asc"), &key.public_armor)?;
            println!("{variant} {}", key.fingerprint);

            // Read back what was just written, so the round trip through the armor is
            // tested rather than assumed.
            let (parsed, _) = SignedSecretKey::from_armor_single(key.secret_armor.as_bytes())?;
            println!("  parsed, {} secret subkey(s)", parsed.secret_subkeys.len());
        }
    }
    Ok(())
}
