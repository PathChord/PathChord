use std::process::ExitCode;

use clap::Parser;
use pathchord_cli::{Cli, run};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pathchord: {error}");
            ExitCode::FAILURE
        }
    }
}
