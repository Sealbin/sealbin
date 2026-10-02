# Test vectors

Draft v1, unstable until 1.0 ([#47](https://github.com/Sealbin/sealbin/issues/47)).

Test vectors for the format defined in
[../handoff-format.md](../handoff-format.md). The vectors are added by
[#3](https://github.com/Sealbin/sealbin/issues/3), with the crypto and envelope
cases from [#4](https://github.com/Sealbin/sealbin/issues/4). The worked
example in Appendix A of the spec becomes the first vector here.

## Layout

One JSON file per vector, named `<name>.json`, or one file holding an array of
vector objects. Every binary value is lowercase hex, with no `0x` prefix and no
separators.

## Schema

| Member | Type | Meaning |
| :--- | :--- | :--- |
| `name` | string | unique, stable id for the vector |
| `description` | string | one line, what the vector shows |
| `inputs` | object | the inputs below |
| `outputs` | object | the expected values below; absent on a negative vector |
| `expect_error` | string | negative vectors only: one of the error names listed under Negative vectors |

`inputs`:

| Member | Type | Meaning |
| :--- | :--- | :--- |
| `k_link` | hex | 32 bytes |
| `password` | string or null | the password before normalisation; `null` means no password |
| `iterations` | integer | PBKDF2 iterations; `0` when `password` is `null` |
| `salt` | hex | 16 bytes |
| `nonce` | hex | 16 bytes |
| `chunk_size` | integer | `65536` in v1 |
| `plaintext` | hex | the whole plaintext: `u32 BE len(inner metadata) || inner metadata || content` (§7); the authoritative input |
| `inner_metadata` | object, optional | an informative decoded view of the metadata; MUST match `plaintext` when present |
| `content` | hex, optional | an informative decoded view of the content; MUST match `plaintext` when present |

`plaintext` is authoritative and a vector MUST give it. `inner_metadata` and
`content` are an optional decoded view for a human reader; two serialisers can
render the same metadata differently, so they are never the source of truth,
and when present they MUST match `plaintext`.

`outputs`:

| Member | Type | Meaning |
| :--- | :--- | :--- |
| `p` | hex or null | the PBKDF2 output; `null` without a password |
| `ikm` | hex | 32 bytes without a password, 64 with |
| `k_payload` | hex | 32 bytes |
| `read_token` | hex | 32 bytes |
| `read_verifier` | hex | 32 bytes |
| `header` | hex | 49 bytes |
| `aad` | hex | 32 bytes |
| `envelope` | hex | the header followed by the ciphertext chunks |

The `envelope` output is the `header` followed by every ciphertext chunk.

## Example

The Appendix A example, as the first vector:

```json
{
  "name": "appendix-a-text-password",
  "description": "Appendix A: a password-protected text seal in a single chunk.",
  "inputs": {
    "k_link": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "password": "correct horse battery staple",
    "iterations": 600000,
    "salt": "202122232425262728292a2b2c2d2e2f",
    "nonce": "303132333435363738393a3b3c3d3e3f",
    "chunk_size": 65536,
    "plaintext": "000000687b226b696e64223a2274657874222c22636f6e74656e745f74797065223a22746578742f706c61696e3b20636861727365743d7574662d38222c2273697a65223a31332c22637265617465645f6174223a22323032362d31302d30325431323a30303a30305a227d68656c6c6f2c206167656e740a",
    "inner_metadata": {
      "kind": "text",
      "content_type": "text/plain; charset=utf-8",
      "size": 13,
      "created_at": "2026-10-02T12:00:00Z"
    },
    "content": "68656c6c6f2c206167656e740a"
  },
  "outputs": {
    "p": "7e5a418e0ee349197a01a04c3021259037906f00bfe3694a3ae1c3b850846fe1",
    "ikm": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f7e5a418e0ee349197a01a04c3021259037906f00bfe3694a3ae1c3b850846fe1",
    "k_payload": "6828fbc1af98405063d64aa995e0d9b02028ea94bcea14c1405620d30aa535a7",
    "read_token": "81380706ba73cf19a28e9892d347bb430c70281c2c302d24ef85b9b97814756c",
    "read_verifier": "812acc918fea97f2401f386918713593b4dcc8c6aabd248f6b02b815b98a5f56",
    "header": "5345414c42494e0101000927c0202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000",
    "aad": "64060ebe509d597543be3251ac324e832993b6739f2d437090bd2bb0760c3a8d",
    "envelope": "5345414c42494e0101000927c0202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000a4f786b1d51e25b44012e0d9933d7a47b085763a7c54531559ce5cb68eacfec0021b7cbe4312e89e49d265125d20d251cab53d5f43f498194b44271d46b3e865d5128cf08bcc4c19a936e509fc9037db2730be3d651b3210f9a0e90e0a4688d2d77a212aebb65cba7dc0648639893514d8c84f0ce9a6bb366a115bd4a51fb6f5451d55169c9ab9c117"
  }
}
```

## Negative vectors

A negative vector carries `expect_error` and no `outputs`. `expect_error` MUST
be one of the names in the spec: `link/missing-key`, `link/bad-key`,
`link/duplicate-key`, `link/bad-id`, `envelope/bad-magic`,
`envelope/unsupported-version`, `envelope/unknown-flags`,
`envelope/bad-header`, `envelope/truncated`, `envelope/auth-failed`,
`payload/bad-metadata`, `payload/unknown-kind`, `payload/size-mismatch`,
`payload/bad-name`, `bundle/refused`.

The vectors must cover at least these cases:

| Case | `expect_error` |
| :--- | :--- |
| input ends inside the header, or a chunk is short, or there are no chunks | `envelope/truncated` |
| two chunks swapped | `envelope/auth-failed` |
| version byte `0x02` | `envelope/unsupported-version` |
| a reserved flag bit set | `envelope/unknown-flags` |
| wrong `K_link`, or wrong password | `envelope/auth-failed` |
| an empty final chunk appended after a genuine final chunk | `envelope/auth-failed` |
| an all-zero salt with the password flag set | `envelope/bad-header` |
| no `key` parameter | `link/missing-key` |
| a 42-character `key` | `link/bad-key` |

The `inputs` are the same shape as a positive vector, except that a vector
wanting a specific malformed envelope gives it directly as an `envelope` (hex)
input.
