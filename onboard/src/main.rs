//! The onboarding handler's binary: the FastCGI responder, started by rc.d.
//!
//! `kyriakon-onboard serve [--config PATH]`
//!
//! The argument handling is the whole of what is here. The responder, its routes
//! and the pages they render are the crate's library, so the drain, the console
//! and the capsule's own pages read the same code the web form does rather than
//! agreeing with it by convention.

use std::path::PathBuf;

use kyriakon_onboard::{config, responder};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kyriakon-onboard: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => {}
        Some(other) => {
            return Err(format!(
                "unknown command {other:?}; usage: kyriakon-onboard serve [--config PATH]"
            ))
        }
        None => return Err("usage: kyriakon-onboard serve [--config PATH]".to_string()),
    }
    let mut cfg_path = PathBuf::from("/etc/onboard/onboard.toml");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(args.next().ok_or("--config needs a path")?);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    responder::serve(config::Config::load(&cfg_path)?).await
}
