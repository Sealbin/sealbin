//! Regenerate the committed test vectors under `spec/vectors/`.
//!
//! `cargo run -p sealbin-format --example gen-vectors`
//!
//! The same generation code is exercised by `tests/vectors.rs`, which
//! regenerates in memory and compares the result to the committed files byte
//! for byte.

mod vectors;

use std::fs;
use std::path::Path;

fn main() {
    let dir = Path::new(vectors::VECTORS_DIR);
    fs::create_dir_all(dir).expect("create the vectors directory");

    for (file, contents) in [
        ("v1-basic.json", vectors::render(&vectors::basic())),
        ("v1-negative.json", vectors::render(&vectors::negative())),
        (
            "v1-agent-keys.json",
            vectors::render(&vectors::agent_keys()),
        ),
    ] {
        let path = dir.join(file);
        fs::write(&path, contents).expect("write a vector file");
        println!("wrote {}", path.display());
    }
}
