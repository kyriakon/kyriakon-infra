//! The onboarding handler's binary: the FastCGI responder, started by rc.d.
//!
//! `kyriakon-onboard serve [--config PATH]`
//!
//! The argument handling is the whole of what is here. The responder, its routes
//! and the pages they render are the crate's library, so the drain, the console
//! and the capsule's own pages read the same code the web form does rather than
//! agreeing with it by convention.

use std::path::PathBuf;

use kyriakon_onboard_core::config;
use kyriakon_onboard_handler::responder;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        e.report("starting the responder");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), responder::Error> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => {}
        Some(other) => {
            return Err(responder::Error::Startup(format!(
                "unknown command {other:?}; usage: kyriakon-onboard serve [--config PATH]"
            )))
        }
        None => {
            return Err(responder::Error::Startup(
                "usage: kyriakon-onboard serve [--config PATH]".to_string(),
            ))
        }
    }
    let mut cfg_path = PathBuf::from("/etc/onboard/onboard.toml");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(args.next().ok_or_else(|| {
                    responder::Error::Failed("--config needs a path".to_string())
                })?);
            }
            other => {
                return Err(responder::Error::Startup(format!(
                    "unknown argument {other:?}"
                )))
            }
        }
    }

    responder::serve(config::Config::load(&cfg_path)?).await
}
