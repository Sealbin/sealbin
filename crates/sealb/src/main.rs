//! `sealb` — the Sealbin command-line tool.
//!
//! It sends and opens handoffs from a terminal, and `sealb mcp` runs the MCP
//! server over stdio so agents (Claude Code, Codex, …) can call it directly
//! (D15; issues #18–#23). At the scaffold (#1) only `--version` is implemented.

use std::process::ExitCode;

const USAGE: &str = "\
sealb - seal a handoff and hand it to another agent

Usage:
    sealb --version
    sealb mcp        an MCP server over stdio (not implemented yet)

Commands arrive issue by issue: https://github.com/sealbin/sealbin/issues";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("sealb {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("sealb: unknown argument `{other}`");
            eprintln!();
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}
