//! The committed test vectors: regenerated here, compared byte for byte, then
//! used to exercise the public API.

#[path = "../examples/gen-vectors/vectors.rs"]
mod vectors;

use std::fs;

use sealbin_format::{Header, Ikm, KeySchedule, Link, LinkKey, ReadToken, open_with_ikm};
use sha2::Sha256;

fn link_key(hex: &str) -> LinkKey {
    LinkKey::from_bytes(vectors::unhex(hex).try_into().unwrap())
}

fn bytes32(hex: &str) -> [u8; 32] {
    vectors::unhex(hex).try_into().unwrap()
}

fn committed(name: &str) -> String {
    fs::read_to_string(format!("{}/{name}", vectors::VECTORS_DIR)).unwrap()
}

#[test]
fn committed_vectors_match_the_generator() {
    assert_eq!(
        vectors::render(&vectors::basic()),
        committed("v1-basic.json"),
        "v1-basic.json is stale; run `cargo run -p sealbin-format --example gen-vectors`"
    );
    assert_eq!(
        vectors::render(&vectors::negative()),
        committed("v1-negative.json"),
        "v1-negative.json is stale; run `cargo run -p sealbin-format --example gen-vectors`"
    );
}

/// Every positive vector must be internally consistent: its key schedule must
/// reproduce the outputs, and its envelope must open back to its plaintext.
#[test]
fn positive_vectors_open() {
    for vector in vectors::basic() {
        let name = vector["name"].as_str().unwrap();
        let inputs = &vector["inputs"];
        let outputs = &vector["outputs"];

        let key = link_key(inputs["k_link"].as_str().unwrap());
        let plaintext = vectors::unhex(inputs["plaintext"].as_str().unwrap());
        let header_hex = outputs["header"].as_str().unwrap().to_owned();
        let header = Header::decode(&vectors::unhex(&header_hex)).unwrap();
        assert_eq!(
            header_hex,
            vectors::hex(&header.encode()),
            "{name}: header must round-trip"
        );

        let ikm = if inputs["password"].is_null() {
            assert_eq!(header.iterations(), 0, "{name}: no-password vector");
            Ikm::from_link_key(&key)
        } else {
            let salt: [u8; 16] = vectors::unhex(inputs["salt"].as_str().unwrap())
                .try_into()
                .unwrap();
            let iterations = u32::try_from(inputs["iterations"].as_u64().unwrap()).unwrap();
            let mut p = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(
                inputs["password"].as_str().unwrap().as_bytes(),
                &salt,
                iterations,
                &mut p,
            );
            assert_eq!(
                vectors::hex(&p),
                outputs["p"].as_str().unwrap(),
                "{name}: PBKDF2"
            );
            Ikm::from_link_key_and_password_key(&key, &p)
        };

        let schedule = KeySchedule::derive(&ikm, &header);
        assert_eq!(
            outputs["ikm"].as_str().unwrap(),
            vectors::hex(ikm.as_bytes()),
            "{name}: ikm"
        );
        assert_eq!(
            outputs["k_payload"].as_str().unwrap(),
            vectors::hex(schedule.payload.as_bytes()),
            "{name}: k_payload"
        );
        assert_eq!(
            outputs["read_token"].as_str().unwrap(),
            vectors::hex(schedule.read_token.as_bytes()),
            "{name}: read_token"
        );
        assert_eq!(
            outputs["read_verifier"].as_str().unwrap(),
            vectors::hex(&schedule.read_token.verifier()),
            "{name}: read_verifier"
        );
        assert_eq!(
            outputs["aad"].as_str().unwrap(),
            vectors::hex(&header.aad()),
            "{name}: aad"
        );

        let envelope = vectors::unhex(outputs["envelope"].as_str().unwrap());
        assert_eq!(
            open_with_ikm(&ikm, &envelope).unwrap(),
            plaintext,
            "{name}: open"
        );
    }
}

#[test]
fn appendix_a_matches_the_specification() {
    let vector = &vectors::basic()[0];
    assert_eq!(vector["name"], "appendix-a-text-password");
    let outputs = &vector["outputs"];
    let expected = [
        (
            "p",
            "7e5a418e0ee349197a01a04c3021259037906f00bfe3694a3ae1c3b850846fe1",
        ),
        (
            "ikm",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f7e5a418e0ee349197a01a04c3021259037906f00bfe3694a3ae1c3b850846fe1",
        ),
        (
            "k_payload",
            "6828fbc1af98405063d64aa995e0d9b02028ea94bcea14c1405620d30aa535a7",
        ),
        (
            "read_token",
            "81380706ba73cf19a28e9892d347bb430c70281c2c302d24ef85b9b97814756c",
        ),
        (
            "read_verifier",
            "812acc918fea97f2401f386918713593b4dcc8c6aabd248f6b02b815b98a5f56",
        ),
        (
            "header",
            "5345414c42494e0101000927c0202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000",
        ),
        (
            "aad",
            "64060ebe509d597543be3251ac324e832993b6739f2d437090bd2bb0760c3a8d",
        ),
        (
            "envelope",
            "5345414c42494e0101000927c0202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000a4f786b1d51e25b44012e0d9933d7a47b085763a7c54531559ce5cb68eacfec0021b7cbe4312e89e49d265125d20d251cab53d5f43f498194b44271d46b3e865d5128cf08bcc4c19a936e509fc9037db2730be3d651b3210f9a0e90e0a4688d2d77a212aebb65cba7dc0648639893514d8c84f0ce9a6bb366a115bd4a51fb6f5451d55169c9ab9c117",
        ),
    ];
    for (member, value) in expected {
        assert_eq!(outputs[member].as_str().unwrap(), value, "{member}");
    }
    assert_eq!(
        vectors::unhex(vector["inputs"]["plaintext"].as_str().unwrap()).len(),
        121
    );
}

#[test]
fn appendix_a_link_parses_and_round_trips() {
    let text = "https://sealb.in/s/k7Qx9pL2Hd4m#key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let link = Link::parse(text).unwrap();
    let mut expected = [0u8; 32];
    for (i, byte) in expected.iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }
    assert_eq!(link.key().as_bytes(), &expected);
    assert_eq!(link.to_string(), text);
}

#[test]
fn negative_vectors_fail_with_their_code() {
    for vector in vectors::negative() {
        let name = vector["name"].as_str().unwrap();
        let expect = vector["expect_error"].as_str().unwrap();
        let inputs = &vector["inputs"];
        let error = if let Some(link) = inputs["link"].as_str() {
            Link::parse(link).unwrap_err()
        } else {
            let key = link_key(inputs["k_link"].as_str().unwrap());
            let envelope = vectors::unhex(inputs["envelope"].as_str().unwrap());
            sealbin_format::open_bytes(&key, &envelope).unwrap_err()
        };
        assert_eq!(error.code(), expect, "{name}");
    }
}

#[test]
fn read_token_verifier_is_constant_time() {
    let token = ReadToken::from_bytes(bytes32(
        "81380706ba73cf19a28e9892d347bb430c70281c2c302d24ef85b9b97814756c",
    ));
    assert!(token.verify(&token.verifier()));
    assert!(!token.verify(&[0u8; 32]));
}
