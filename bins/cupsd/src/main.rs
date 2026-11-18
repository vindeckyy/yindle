//! `cupsd` binary entrypoint.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    cupsd::run_cli(std::env::args_os().skip(1))
}
