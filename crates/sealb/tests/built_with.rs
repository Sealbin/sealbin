//! The built-with list, checked against the data it is generated from.
//!
//! Three things can go wrong here and each has a test: a vendored entry that no
//! longer matches the published registry (drift, network-gated), a render that
//! hides or softens a status (the guard that nothing planned is shown as live),
//! and the hand-written `web/open.html` copy drifting from the same data
//! (parity).
//!
//! The tests read `crates/sealb/data/stack.json` rather than hard-coding the
//! names, so re-vendoring from the registry is a one-file change and a failure
//! only happens when the render or the HTML disagrees with the data.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The binary built for this test run, whichever profile cargo chose.
const SEALB: &str = env!("CARGO_BIN_EXE_sealb");

/// The published Factory Zero registry. The vendored copy is one entry of it.
const REGISTRY_URL: &str = "https://factory0.ventures/stack.json";

/// This venture's id in the registry.
const VENTURE_ID: &str = "FZ-016";

/// The statuses the registry publishes, in words. Anything else is not one.
const STATUSES: [&str; 2] = ["live", "planned"];

/// The repository root, so this test finds `web/open.html` from the crate.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/sealb is two levels below the repository root")
        .to_path_buf()
}

/// The vendored registry entry, as JSON.
fn vendored() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/stack.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

/// The `uses` array of the vendored entry.
fn uses() -> Vec<Value> {
    vendored()["uses"]
        .as_array()
        .expect("vendored stack.json has no `uses` array")
        .clone()
}

/// Runs `sealb about` and returns its stdout.
fn about() -> String {
    let out = Command::new(SEALB)
        .arg("about")
        .output()
        .expect("failed to run sealb");
    assert!(out.status.success(), "sealb about exited non-zero");
    String::from_utf8(out.stdout).expect("stdout was not UTF-8")
}

/// The status word of each rendered row: every indented line of the block, which
/// is the entry rows only.
fn rendered_statuses(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .map(|line| {
            line.split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[test]
fn about_lists_every_registry_entry_with_its_link_phrase_and_status() {
    let stdout = about();
    assert_eq!(
        uses().len(),
        7,
        "the registry entry should carry 7 uses; if the registry changed, \
         update this count and the vendored copy together"
    );
    for use_ in uses() {
        for field in ["name", "url", "phrase", "status"] {
            let value = use_[field]
                .as_str()
                .unwrap_or_else(|| panic!("vendored use has no string `{field}`"));
            assert!(
                stdout.contains(value),
                "`sealb about` is missing {field} `{value}` of {}:\n{stdout}",
                use_["name"].as_str().unwrap_or_default()
            );
        }
    }
    assert_eq!(
        rendered_statuses(&stdout).len(),
        7,
        "every registry entry should get exactly one row:\n{stdout}"
    );
}

#[test]
fn about_spells_out_two_live_and_five_planned() {
    let statuses = rendered_statuses(&about());
    let live = statuses.iter().filter(|s| *s == "live").count();
    let planned = statuses.iter().filter(|s| *s == "planned").count();
    assert_eq!(
        (live, planned, statuses.len()),
        (2, 5, 7),
        "the registry says two entries are live and five are planned, so no \
         planned entry may be shown as live; got {statuses:?}"
    );
    for status in &statuses {
        assert!(
            STATUSES.contains(&status.as_str()),
            "statuses are spelled in words, got `{status}` in {statuses:?}"
        );
    }
}

#[test]
fn about_includes_the_subprocessors_url() {
    let stdout = about();
    assert!(
        stdout.contains("https://factory0.ventures/ventures/sealbin/"),
        "the subprocessors link is the registry page; sealb.in has no privacy \
         page yet, so it stands in. Got:\n{stdout}"
    );
}

/// The HTML page cannot be generated from the JSON (D1: the pages stay vanilla
/// HTML, copied by `web/build.sh`), so this is the guard on the hand copy.
#[test]
fn the_open_page_carries_every_registry_name_and_url() {
    let html = std::fs::read_to_string(repo_root().join("web/open.html"))
        .expect("could not read web/open.html");
    for use_ in uses() {
        for field in ["name", "url"] {
            let value = use_[field]
                .as_str()
                .unwrap_or_else(|| panic!("vendored use has no string `{field}`"));
            assert!(
                html.contains(value),
                "web/open.html is missing {field} `{value}`; it must be kept in \
                 step with crates/sealb/data/stack.json"
            );
        }
    }
}

/// Network-gated: the vendored copy must equal what the registry publishes.
///
/// Run with `cargo test -p sealb --test built_with -- --ignored`. In CI this is
/// the step next to the test job, so a registry edit that never reached this
/// repository fails the build.
#[test]
#[ignore = "needs network; run with: cargo test -- --ignored"]
fn vendored_entry_matches_published_registry() {
    let Some(published) = fetch(REGISTRY_URL) else {
        // No network, no curl, or a registry outage: say so and pass. The drift
        // itself is still caught the next time CI has the network.
        return;
    };
    let registry: Value =
        serde_json::from_str(&published).expect("the registry did not serve valid JSON");

    let entry = registry["ventures"]
        .as_array()
        .expect("the registry has no `ventures` array")
        .iter()
        .find(|v| v["id"].as_str() == Some(VENTURE_ID))
        .unwrap_or_else(|| {
            panic!("the registry no longer has a ventures[] entry with id `{VENTURE_ID}`")
        });

    // `Value` equality is semantic: object key order does not matter, but every
    // field of the published entry does, including ones we do not render yet.
    let vendored = vendored();
    assert!(
        *entry == vendored,
        "crates/sealb/data/stack.json has drifted from the entry the registry \
         now publishes for {VENTURE_ID}.\n\
         {}\n\
         The registry is the source of truth and changes first: update {REGISTRY_URL} \
         if it is wrong there, then re-vendor this file from the published \
         `ventures[]` entry and update the retrieval date in data/PROVENANCE.md. \
         Do not edit this file to silence the difference.",
        differences(entry, &vendored)
    );
}

/// Names what changed, one line per changed field, rather than leaving the
/// maintainer to diff two JSON blobs by eye. Differences are reported from the
/// registry's point of view: what the registry now says the vendored copy does
/// not.
fn differences(published: &Value, vendored: &Value) -> String {
    let mut out = String::new();
    for field in ["name", "site", "page"] {
        if published[field] != vendored[field] {
            let _ = writeln!(
                out,
                "  {field}: registry has {}, the vendored copy has {}",
                published[field], vendored[field]
            );
        }
    }

    let published_uses = published["uses"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let vendored_uses = vendored["uses"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    for (index, use_) in published_uses.iter().enumerate() {
        let id = use_["id"].as_str().unwrap_or("<no id>");
        match vendored_uses.iter().find(|v| v["id"] == use_["id"]) {
            None => {
                let _ = writeln!(
                    out,
                    "  use {id}: in the registry, missing from the vendored copy"
                );
            }
            Some(mine) if mine != use_ => {
                let _ = writeln!(out, "  use {id}:");
                for field in ["name", "kind", "url", "role", "phrase", "status", "note"] {
                    if use_[field] != mine[field] {
                        let _ = writeln!(
                            out,
                            "    {field}: registry has {}, the vendored copy has {}",
                            use_[field], mine[field]
                        );
                    }
                }
                // Same values, so the difference is where the use sits, which
                // the render exposes as order.
                let at = vendored_uses
                    .iter()
                    .position(|v| v["id"] == use_["id"])
                    .unwrap_or(index);
                if at != index && use_ == mine {
                    let _ = writeln!(
                        out,
                        "    position: registry index {index}, the vendored copy \
                         has it at {at}; the render shows registry order"
                    );
                }
            }
            Some(_) => {}
        }
    }
    for use_ in vendored_uses {
        if !published_uses.iter().any(|v| v["id"] == use_["id"]) {
            let _ = writeln!(
                out,
                "  use {}: only in the vendored copy; the registry no longer lists it",
                use_["id"].as_str().unwrap_or("<no id>")
            );
        }
    }

    if out.is_empty() {
        // Every field of every use matches, so the entries themselves agree and
        // the difference is in the array's order or in a field this report does
        // not walk. Say so rather than claiming nothing changed.
        return "  every use matches field for field, so the entries themselves \
                agree: the vendored copy differs in the `uses` order or in a \
                field not listed above. Copy the published entry verbatim"
            .to_owned();
    }
    out.trim_end().to_owned()
}

/// Fetches a URL with `curl`, the one HTTPS client a no-dependency test can
/// rely on. `None` means "could not fetch", which the caller treats as a skip.
fn fetch(url: &str) -> Option<String> {
    let out = match Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "30",
            url,
        ])
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("skipping: could not run curl ({e}); is curl on PATH?");
            return None;
        }
    };
    if !out.status.success() {
        eprintln!(
            "skipping: curl could not fetch {url} ({}) — no network, or the \
             registry is unreachable. The vendored copy was not compared.",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }
    String::from_utf8(out.stdout).ok()
}
