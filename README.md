# The Jinn Wire Grammar

The paper ([jinncore.org](https://jinncore.org)) is the theory: three mandates,
two axioms, and a set of refusals. This repository is the first artifact the
paper promises after itself: the wire grammar, the exact bytes that make the
mandates checkable. It contains three things and refuses to contain more.

- **`SPEC.md`** — the wire grammar. Canonical serialization, the envelope,
  the three attestation species, the membership pair. Normative where the
  code demonstrates it, and explicitly provisional everywhere else.
- **`src/`** — the reference implementation, in TypeScript. A verification
  library, not a framework: it signs, verifies, and refuses, and does
  nothing else.
- **`test-vectors/`** — language-neutral vectors: canonical bytes in,
  expected signatures and verdicts out, forgeries included. Conformance
  means matching these, not linking this library.

## Deliberately absent

The same discipline that shapes the paper shapes this repository. Below the
waist is never mandated, so there is no runtime, no lamp-keeping, no key
custody beyond "the caller holds the bytes." Above the waist is never
decided, so there is no transport, no discovery, no directory, no score.
An envelope that verifies here verifies arriving by HTTP, queue, chat
message, or QR code; how it arrived is not this artifact's business.

## Status

Version 0.0.x: the three mandates are normative and implemented.
Canonical serialization and the SHA-256 digest; identity; the envelope
(sign, verify, audience gate, replay window, presented standing); and the
attestation grammar (capability with delegation chains, testimony, the
membership pair). Next: the worked examples from the paper's section 6
and the language-neutral test vectors. Nothing here is stable yet.

## Vocabulary

Sigil, genie, lamp, body, jinn: defined once, in the paper's section 2, and
used here without redefinition.
