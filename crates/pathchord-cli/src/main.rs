use std::process::ExitCode;

use clap::Parser;
use pathchord_cli::{Cli, run};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pathchord: {error}");
            ExitCode::FAILURE
        }
    }
}
