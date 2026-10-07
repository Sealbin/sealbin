//! `sealb --version` prints the workspace version, so `-V` and the crate
//! version can never drift. It then names where the built-with list comes
//! from, so the claim that the list is generated from the Factory Zero registry
//! is visible from the tool itself.

use std::process::Command;

/// The binary built for this test run, whichever profile cargo chose.
const SEALB: &str = env!("CARGO_BIN_EXE_sealb");

/// The exact stdout of `--version`: the version line, unaltered and first, then
/// the source of the built-with data.
fn expected() -> String {
    format!(
        "sealb {}\nBuilt-with data: https://factory0.ventures/stack.json",
        env!("CARGO_PKG_VERSION")
    )
}

#[test]
fn version_flag_prints_workspace_version() {
    let out = Command::new(SEALB)
        .arg("--version")
        .output()
        .expect("failed to run sealb");
    assert!(out.status.success(), "sealb --version exited non-zero");
    assert_eq!(
        String::from_utf8(out.stdout)
            .expect("stdout was not UTF-8")
            .trim(),
        expected(),
    );
}

#[test]
fn short_version_flag_matches() {
    let out = Command::new(SEALB)
        .arg("-V")
        .output()
        .expect("failed to run sealb");
    assert!(out.status.success(), "sealb -V exited non-zero");
    assert_eq!(
        String::from_utf8(out.stdout)
            .expect("stdout was not UTF-8")
            .trim(),
        expected(),
    );
}

#[test]
fn version_line_names_the_built_with_source_of_truth() {
    let out = Command::new(SEALB)
        .arg("--version")
        .output()
        .expect("failed to run sealb");
    let stdout = String::from_utf8(out.stdout).expect("stdout was not UTF-8");
    assert!(
        stdout.contains("https://factory0.ventures/stack.json"),
        "--version should name the registry the built-with data is vendored from, got: {stdout}"
    );
}

#[test]
fn unknown_argument_prints_usage_to_stderr_and_fails() {
    let out = Command::new(SEALB)
        .arg("nonsense")
        .output()
        .expect("failed to run sealb");
    assert!(!out.status.success(), "sealb nonsense should exit non-zero");
    assert!(out.stdout.is_empty(), "usage must go to stderr, not stdout");
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr was not UTF-8")
            .contains("Usage:"),
        "stderr should carry the usage",
    );
}
