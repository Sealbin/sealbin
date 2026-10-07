//! The "Built with" list: which sister ventures and third parties Sealbin runs
//! on, and which are only decided.
//!
//! The data is vendored, not fetched. `data/stack.json` is a verbatim copy of
//! Sealbin's entry (`FZ-016`) in the Factory Zero registry, and `build.rs`
//! compiles it into the [`ENTRIES`] table at build time. Nothing here opens a
//! socket, and the shipped binary gains no dependency for it — a product that
//! claims what it is built from should still start on a plane.
//!
//! The registry is authoritative and changes first (`data/PROVENANCE.md`); the
//! vendored copy follows it. A network-gated test in `tests/built_with.rs`
//! fails the build when the two drift apart.
//!
//! Two rules the render keeps whatever the data says:
//!
//! - entries appear in registry order, unreshuffled; and
//! - the status is always spelled as the word `live` or `planned`. It is never
//!   implied by position, colour or styling, because "planned" shown as "live"
//!   is a false claim about what runs today, and that is the one mistake this
//!   section cannot make.

/// One thing Sealbin uses, as published in the registry.
///
/// The whole registry entry is carried, not just the fields today's render
/// prints: it is the vendored copy, and dropping fields here would make the
/// table disagree with `data/stack.json` for no gain.
#[allow(dead_code)]
pub struct Entry {
    /// The registry's id for it: `FZ-0nn` for a sister venture, a slug for a
    /// third party.
    pub id: &'static str,
    /// Its display name.
    pub name: &'static str,
    /// Where it lives, so every line is a link.
    pub url: &'static str,
    /// What it is used for, as a machine-readable slug (`payments`, `hosting`).
    pub role: &'static str,
    /// How the sentence reads: "Payments by", "Hosted on".
    pub phrase: &'static str,
    /// `live` (in use today) or `planned` (decided, not in use yet). The
    /// registry publishes no other value.
    pub status: &'static str,
    /// One sentence on what specifically is used.
    pub note: &'static str,
    /// `factory-zero` for a sister venture, `third-party` otherwise.
    pub kind: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/built_with.rs"));

/// Renders the whole block `sealb about` prints: the entries in registry order
/// with the status spelled out, then the subprocessors and source links.
///
/// Columns are padded with plain `format!` width, matching the rest of the
/// CLI's no-dependency plain text.
#[must_use]
pub fn render() -> String {
    let status_width = width(ENTRIES.iter().map(|e| e.status.len()));
    let phrase_width = width(ENTRIES.iter().map(|e| e.phrase.len()));
    let name_width = width(ENTRIES.iter().map(|e| e.name.len()));

    let mut lines = vec![String::from("Built with")];
    for entry in ENTRIES {
        lines.push(format!(
            "  {status:<status_width$}  {phrase:<phrase_width$}  {name:<name_width$}  {url}",
            status = entry.status,
            phrase = entry.phrase,
            name = entry.name,
            url = entry.url,
            status_width = status_width,
            phrase_width = phrase_width,
            name_width = name_width,
        ));
    }
    lines.push(String::new());
    lines.push(format!("Subprocessors: {PAGE}"));
    lines.push(format!("Source: {SOURCE}"));
    lines.join("\n") + "\n"
}

/// The widest of the given lengths, so one column fits its longest cell.
fn width(lengths: impl Iterator<Item = usize>) -> usize {
    lengths.max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{ENTRIES, render};

    #[test]
    fn every_entry_is_live_or_planned() {
        for entry in ENTRIES {
            assert!(
                matches!(entry.status, "live" | "planned"),
                "{} has status {:?}, which is neither live nor planned",
                entry.name,
                entry.status
            );
        }
    }

    #[test]
    fn the_block_ends_with_the_subprocessors_and_source_links() {
        let out = render();
        assert!(out.contains("Subprocessors: https://factory0.ventures/ventures/sealbin/"));
        assert!(out.contains("Source: https://factory0.ventures/stack.json"));
    }
}
