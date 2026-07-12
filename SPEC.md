# The Jinn Wire Grammar

**Version 0.0.2 (unstable).** This document fixes the bytes of the Jinn
protocol: how wire objects are serialized, what a signature covers, and what
a verifier must reject. It is the artifact the paper defers to for
canonicalization, "a wire-grammar obligation" (paper, section 4.3). The
paper defines the theory and the vocabulary; nothing is redefined here.

Sections marked **normative** are demonstrated by the reference
implementation and covered by test vectors. Sections marked **provisional**
describe intent and may change without notice until marked normative.

## 1. Scope

This grammar fixes exactly four things.

1. The canonical serialization every signature is computed over (section 3).
2. The identity primitive: key algorithm and encoding (section 4).
3. The envelope: fields, signing, and verification (section 5).
4. The attestation species and the membership pair (section 6).

It refuses to fix transport, discovery, payload meaning, key custody, lamp
mechanics, and anything else the paper places off the waist. Conformance is
byte-level: an implementation conforms if it produces and accepts exactly
the bytes the test vectors say, and rejects exactly what they reject.

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.
"The paper" means "Jinn: A Protocol for Societies of Sovereign Agents";
sigil, genie, lamp, body, and jinn carry the paper's section 2 meanings.
Byte sequences in examples are lowercase hex.

## 3. Canonical Serialization — **normative**

Every wire object is a value serialized as **deterministic CBOR**,
RFC 8949 section 4.2.1 (Core Deterministic Encoding), restricted to the
subset below. The rules are the RFC's; this section only names the subset
and the consequences.

### 3.1 The value subset

A wire value is one of:

- an **integer** in [-2^64, 2^64 - 1] (CBOR major types 0 and 1);
- a **byte string** (major type 2);
- a **UTF-8 text string** (major type 3);
- an **array** of wire values (major type 4);
- a **map** from text-string keys to wire values (major type 5);
- **false**, **true**, or **null** (simple values 20, 21, 22).

Floating-point values, tags, indefinite-length items, simple value 23
(undefined), and all other simple values are outside the grammar.

### 3.2 Deterministic encoding rules

As RFC 8949 section 4.2.1 requires:

- every argument (integer value, string length, container size) MUST use
  its shortest possible encoding;
- all strings, arrays, and maps MUST use definite lengths;
- map keys MUST be unique and MUST appear in bytewise lexicographic order
  of their own encoded bytes.

Consequently every wire value has exactly one valid encoding.

### 3.3 Strict decoding

A verifier MUST reject any input that is not the canonical encoding of a
value in the subset: non-shortest arguments, indefinite lengths, floats,
tags, unknown simple values, non-text or misordered or duplicate map keys,
invalid UTF-8, and trailing bytes after the top-level value. Rejection is
not leniency withheld; two encodings for one value is a forgery surface,
and the grammar closes it by admitting one.

### 3.4 Signing

Wherever this grammar says a key signs an object, the bytes signed are the
canonical encoding of that object, exactly as transmitted. There is no
transformation, hashing convention, or domain separation beyond what the
object's own fields carry; what travels is what was signed.

## 4. Identity — **normative**

A genie's name is an **Ed25519 public key** (RFC 8032), minted by the
genie itself and carried as its 32-byte encoding in a CBOR byte string.
Signatures are 64-byte Ed25519 signatures, likewise carried as byte
strings. Nothing else about a genie is a wire fact: where the secret half
sleeps is custody, below the waist. Hash self-description (`hash(S)` for
sigils) and any succession convention remain **provisional** and deferred.

## 5. Envelope — **normative**

The envelope is the only object the protocol puts on a wire: a map with
exactly these entries and no others.

| key | type | presence | meaning |
|---|---|---|---|
| `v` | integer | required | wire grammar version; this document is version `0` |
| `from` | 32-byte byte string | required | the sender's public key |
| `aud` | 32-byte byte string | optional | audience commitment; absent means public by construction |
| `fresh` | map `{t, n}` | required | freshness marker |
| `payload` | byte string | required | opaque payload; meaning is convention between genies, never protocol law |
| `sig` | 64-byte byte string | required | Ed25519 signature |

The freshness marker `fresh` is a map with exactly two entries: `t`, the
sender's claimed time as a non-negative integer count of seconds, and
`n`, a per-envelope nonce of 8 to 32 bytes (16 random bytes recommended).
`t` is a claim judged against each verifier's own clock; there is no
protocol clock.

**Sealing.** `sig` is the Ed25519 signature over the canonical encoding
(section 3) of the envelope map with the `sig` entry absent. The envelope
then travels as the canonical encoding of the full map. The signature
covers every field, so audience, freshness, and presented standing are
tamper-evident, not just the payload.

**Verification.** A verifier MUST reject an envelope unless all of the
following hold: the bytes are canonical (section 3.3); the map has exactly
the shape above, unknown keys included in the rejection; `v` is a version
the verifier implements; and `sig` verifies against `from` over the
re-encoded body. A verifier that enforces an audience MUST reject a
directed envelope whose `aud` is not its own key; any payload whose safe
handling assumes directed delivery must bind an audience, or the bytes
are replayable to parties the sender never addressed. Freshness is law
with a sovereign dial: each verifier MUST enforce a freshness policy on
its own bounded state, rejecting markers it has already seen and markers
outside a tolerance it alone chooses; the pair `(t, n)` makes this
possible with memory bounded by the tolerance window, since everything
older is rejected on `t` alone and only markers inside the window need
remembering.

**Reserved.** The key `presents` (attestations the sender chooses to
present) is reserved: version-0 envelopes MUST NOT include it until the
attestation grammar (section 6) lands, which will bump the version.

## 6. Attestation — **provisional**

Three species (capability, testimony, membership), one verification path,
expiry as law. The membership pair is the grammar's most delicate
obligation: the jinn's signature over a statement and the member's
countersignature over the hash of that exact statement, where "exact" means
the canonical bytes of section 3. Shapes land here with the code that
demonstrates them.

## 7. Test Vectors

`test-vectors/` holds language-neutral JSON vectors. Each vector gives
inputs, expected canonical bytes, and for verification cases an expected
verdict, including forgeries that MUST be rejected. The vectors, not the
reference implementation, are the conformance surface.

## 8. Change Discipline

Until 0.1.0, anything provisional may change. From 0.1.0, normative
sections change only with a version bump and updated vectors. No section
of this grammar will ever promise delivery, ordering, payload meaning, or
anything the paper's waist refuses.
