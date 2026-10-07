// An independent check of the agent key vectors (spec §14, issue #39).
//
// The Rust tests check the format crate against itself: it produces the
// vectors and it reads them back. This script is the other half of the check.
// It reads spec/vectors/v1-agent-keys.json, rebuilds the signed bytes from the
// vector's own inputs with no help from the crate, and verifies the published
// signatures with WebCrypto — the same API the browser open and activate pages
// use, so a bundle that verifies here verifies in the browser.
//
// Signature verification is deliberately `crypto.subtle`. Node imports a raw
// 32-byte Ed25519 public key as a `verify` key directly, so no SPKI wrapping
// and no node:crypto fallback is needed. node:crypto is used for the one thing
// WebCrypto cannot do here: turn a 32-byte seed into its public key, which the
// rotation vector needs because it names a key by the secret that made it.
//
//   node spec/vectors/check-agent-keys.mjs
//
// Exits 0 when every vector holds, non-zero on the first mismatch.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPrivateKey, createPublicKey } from "node:crypto";

// The domain tags of §14, byte for byte.
const BINDING_TAG = Buffer.from("sealbin/v1/agent-key-binding", "ascii");
const ROTATION_TAG = Buffer.from("sealbin/v1/agent-key-rotation", "ascii");

// The Crockford base32 alphabet of §14, in value order: `i`, `l`, `o` and `u`
// are absent so a hand-copied key id cannot turn one character into another.
const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

// DER AlgorithmIdentifier prefixes, from the PKCS#8 shape of an Ed25519 and an
// X25519 seed. Node will not take a bare seed, so the seed is wrapped in the
// minimum PKCS#8 that OpenSSL accepts and the public key is read back off the
// end of the SPKI, where it is the last 32 bytes.
const PKCS8_ED25519 = "300506032b6570";
const PKCS8_X25519 = "300506032b656e";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "v1-agent-keys.json"), "utf8"));

let failures = 0;

function check(what, actual, expected) {
  if (actual === expected) {
    console.log(`  ok    ${what}`);
    return;
  }
  failures += 1;
  console.error(`  FAIL  ${what}`);
  console.error(`          got      ${actual}`);
  console.error(`          expected ${expected}`);
}

/// The bytes an Ed25519 or X25519 secret becomes its public key: the seed in a
/// minimal PKCS#8, through OpenSSL, back out as a SPKI.
function publicFromSecret(pkcs8Oid, secretHex) {
  const inner = Buffer.concat([Buffer.from([0x04, 0x20]), Buffer.from(secretHex, "hex")]);
  const octets = Buffer.concat([Buffer.from([0x04, inner.length]), inner]);
  const body = Buffer.concat([Buffer.from([0x02, 0x01, 0x00]), Buffer.from(pkcs8Oid, "hex"), octets]);
  const pkcs8 = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("hex");
}

/// `u32be(len(value)) || value` — the two length-prefixed strings of §14.
function lengthPrefixed(value) {
  const bytes = Buffer.from(value, "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}

/// The canonical bytes of §14 that the binding signature covers:
///
/// ```text
/// "sealbin/v1/agent-key-binding"          (28 bytes, ASCII)
///       || u32be(len(agent_name)) || agent_name
///       || u32be(len(account_id)) || account_id
///       || u64be(created_at)
///       || x25519_pub                     (32 bytes)
/// ```
///
/// The Ed25519 public key is not in the message: it is the key the signature is
/// verified against, so it is authenticated by being the verifier.
function bindingMessage({ agent_name, account_id, created_at }, x25519PubHex) {
  const time = Buffer.alloc(8);
  time.writeBigUInt64BE(BigInt(created_at));
  return Buffer.concat([
    BINDING_TAG,
    lengthPrefixed(agent_name),
    lengthPrefixed(account_id),
    time,
    Buffer.from(x25519PubHex, "hex"),
  ]);
}

/// `key_id_bytes = SHA-256(ed25519_pub || x25519_pub)[0..16]`.
async function keyIdBytes(ed25519PubHex, x25519PubHex) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    Buffer.from(ed25519PubHex + x25519PubHex, "hex"),
  );
  return Buffer.from(new Uint8Array(digest).subarray(0, 16));
}

/// 16 bytes as the 26 lower-case Crockford base32 characters of a key id, the
/// last character carrying the final three bits left aligned in its group.
function keyId(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += CROCKFORD[(value << (5 - bits)) & 31];
  }
  return out;
}

/// The fingerprint: the key id in groups of 4, 4, 4, 4 and 10.
function fingerprint(id) {
  return [id.slice(0, 4), id.slice(4, 8), id.slice(8, 12), id.slice(12, 16), id.slice(16)].join("-");
}

/// Import a raw 32-byte Ed25519 public key as a WebCrypto `verify` key.
async function verifyKey(ed25519PubHex) {
  return crypto.subtle.importKey(
    "raw",
    Buffer.from(ed25519PubHex, "hex"),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

async function checkBinding(vector) {
  const { inputs, outputs } = vector;
  const x25519Pub = publicFromSecret(PKCS8_X25519, inputs.x25519_secret);
  check("x25519_pub", x25519Pub, outputs.x25519_pub);
  const ed25519Pub = publicFromSecret(PKCS8_ED25519, inputs.ed25519_secret);
  check("ed25519_pub", ed25519Pub, outputs.ed25519_pub);

  const message = bindingMessage(inputs, x25519Pub);
  check("binding_message", message.toString("hex"), outputs.binding_message);

  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    await verifyKey(ed25519Pub),
    Buffer.from(outputs.binding_signature, "hex"),
    message,
  );
  check("binding_signature verifies under ed25519_pub", ok, true);

  const idBytes = await keyIdBytes(ed25519Pub, x25519Pub);
  check("key_id_bytes", idBytes.toString("hex"), outputs.key_id_bytes);
  check("key_id", keyId(idBytes), outputs.key_id);
  check("fingerprint", fingerprint(outputs.key_id), outputs.fingerprint);
}

/// The canonical bytes of §14 that the rotation signature covers: the domain
/// tag and the new bundle's key id, nothing else.
async function rotationMessage(newEd25519PubHex, newX25519PubHex) {
  return Buffer.concat([ROTATION_TAG, await keyIdBytes(newEd25519PubHex, newX25519PubHex)]);
}

async function checkRotation(vector) {
  const { inputs, outputs } = vector;
  const previousEd25519Pub = publicFromSecret(PKCS8_ED25519, inputs.previous_ed25519_secret);
  const previousX25519Pub = publicFromSecret(PKCS8_X25519, inputs.previous_x25519_secret);
  const newEd25519Pub = publicFromSecret(PKCS8_ED25519, inputs.new_ed25519_secret);
  const newX25519Pub = publicFromSecret(PKCS8_X25519, inputs.new_x25519_secret);

  const previousIdBytes = await keyIdBytes(previousEd25519Pub, previousX25519Pub);
  check("previous_key_id", keyId(previousIdBytes), outputs.previous_key_id);
  const newIdBytes = await keyIdBytes(newEd25519Pub, newX25519Pub);
  check("new_key_id", keyId(newIdBytes), outputs.new_key_id);
  check("new_fingerprint", fingerprint(outputs.new_key_id), outputs.new_fingerprint);

  const message = await rotationMessage(newEd25519Pub, newX25519Pub);
  check("rotation_message", message.toString("hex"), outputs.rotation_message);

  // The signature is made by the *previous* key, so that is the key it is
  // checked against; the incoming key did not hand over to itself.
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    await verifyKey(previousEd25519Pub),
    Buffer.from(outputs.rotation_signature, "hex"),
    message,
  );
  check("rotation_signature verifies under the previous key", ok, true);

  const selfSigned = await crypto.subtle.verify(
    { name: "Ed25519" },
    await verifyKey(newEd25519Pub),
    Buffer.from(outputs.rotation_signature, "hex"),
    message,
  );
  check("rotation_signature does not verify under the new key", selfSigned, false);
}

/// A negative vector carries the full `bundle` to check and the signature that
/// should no longer verify. Here the agent name is one character longer, so the
/// length prefix and the bytes both move.
async function checkRenamed(vector) {
  const { bundle, inputs, expect_error } = vector;
  check("expect_error", expect_error, "agent-keys/bad-binding");
  const message = bindingMessage(bundle, bundle.x25519_pub);
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    await verifyKey(bundle.ed25519_pub),
    Buffer.from(inputs.binding_signature, "hex"),
    message,
  );
  check(`binding does not verify for ${bundle.agent_name}`, ok, false);
}

for (const vector of vectors) {
  console.log(vector.name);
  if (vector.expect_error) {
    await checkRenamed(vector);
  } else if (vector.outputs.rotation_message) {
    await checkRotation(vector);
  } else {
    await checkBinding(vector);
  }
}

if (failures > 0) {
  console.error(`\n${failures} check(s) failed against spec/vectors/v1-agent-keys.json`);
  process.exit(1);
}
console.log(`\nok: ${vectors.length} agent key vectors verified with crypto.subtle`);