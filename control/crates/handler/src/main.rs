//! The handler's binary: the FastCGI responder, started by rc.d.
//!
//! `kyriakon-control serve [--config PATH]`
//!
//! The argument handling is the whole of what is here. The responder, its routes
//! and the pages they render are the crate's library, so the drain, the console
//! and the capsule's own pages read the same code the web form does rather than
//! agreeing with it by convention.

use std::path::PathBuf;

use kyriakon_control_core::config;
use kyriakon_control_handler::responder;

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
            return Err(responder::Error::UnknownCommand {
                command: other.to_string(),
            })
        }
        None => return Err(responder::Error::NoCommand),
    }
    let mut cfg_path = PathBuf::from("/etc/onboard/onboard.toml");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(args.next().ok_or(responder::Error::MissingConfigPath)?);
            }
            other => {
                return Err(responder::Error::UnknownArgument {
                    argument: other.to_string(),
                })
            }
        }
    }

    responder::serve(config::Config::load(&cfg_path)?).await
}
