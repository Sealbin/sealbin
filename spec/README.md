# spec

Draft v1, unstable until 1.0 ([#47](https://github.com/Sealbin/sealbin/issues/47)).

The handoff format spec: the contract every sealbin client and server follows.

| File | What it is |
| :--- | :--- |
| [handoff-format.md](handoff-format.md) | the normative document: link, discovery, keys, envelope, payload, bundle, lifecycle, API, versioning, security |
| [vectors/](vectors/README.md) | the JSON test vectors for the format and the crypto |

The wire format and the crypto in `crates/sealbin-format` follow this spec. A
crypto change needs a spec change and new test vectors in the same pull
request, as [CONTRIBUTING.md](../CONTRIBUTING.md) says.

## Proposing a change

Open an issue that describes the problem first; a spec change is the last step,
not the first. Then a pull request changes the document and the vectors
together. A breaking change needs a new version byte and new HKDF info strings
(§12). Do not report a vulnerability in a public issue; follow
[SECURITY.md](../SECURITY.md).
