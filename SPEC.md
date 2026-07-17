# The Jinn Wire Grammar

**Version 0.0.5 (unstable).** This document fixes the bytes of the Jinn
protocol: how wire objects are serialized, what a signature covers, and what
a verifier must reject. It is the artifact the paper defers to for
canonicalization, "a wire-grammar obligation" (paper, section 4.3). The
paper defines the theory and the vocabulary; nothing is redefined here.

Sections marked **normative** are demonstrated by the reference
implementation and covered by test vectors. Sections marked **provisional**
describe intent and may change without notice until marked normative.

## 1. Scope

This grammar fixes exactly four things.

1. The canonical serialization every signature is computed over, and the
   digest function (section 3).
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
sigil, genie, lamp, and jinn carry the paper's section 2 meanings.
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

Wherever this grammar says a key **signs** an object, the bytes signed are
the canonical encoding of that object, exactly as transmitted: what
travels is what was signed. Wherever it says a key **countersigns** an
object, the bytes signed are the SHA-256 digest (section 3.5) of that
canonical encoding. The two domains never overlap: authorship is always a
signature over an object's own bytes, acceptance always over a digest, so
neither act can be presented as the other. There is no transformation or
domain separation beyond these two rules and what each object's own
fields carry.

### 3.5 Digest

The grammar's digest function is **SHA-256** (FIPS 180-4). Wherever this
document says hash or digest, it is SHA-256 over canonical bytes. One
protocol, one digest: the membership countersignature uses it today, and
sigil naming (`hash(S)`) will use the same function when it lands.

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
| `v` | integer | required | wire grammar version; this document is version `1` |
| `from` | 32-byte byte string | required | the sender's public key |
| `aud` | non-empty array of 32-byte byte strings | optional | the keys this envelope is addressed to, strictly ascending, unique; absent means public by construction |
| `presents` | non-empty array of attestations | optional | standing the sender chooses to present (section 6) |
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
directed envelope whose `aud` does not include its own key; any payload whose safe
handling assumes directed delivery must bind an audience, or the bytes
are replayable to parties the sender never addressed. Freshness is law
with a sovereign dial: each verifier MUST enforce a freshness policy on
its own bounded state, rejecting markers it has already seen and markers
outside a tolerance it alone chooses; the pair `(t, n)` makes this
possible with memory bounded by the tolerance window, since everything
older is rejected on `t` alone and only markers inside the window need
remembering.

**Presenting.** Each entry of `presents` MUST parse as an attestation
(section 6); the envelope signature covers them like every other field,
so presented standing is tamper-evident in transit. An envelope's
validity never implies its cargo's: verifying the presented attestations
themselves (signatures, expiry, chains), and judging whether they
suffice, is the receiving gate's own policy. An empty `presents` array is
a shape error; a sender with nothing to present omits the key.

## 6. Attestation — **normative**

An attestation is a signed, expiring statement of standing: `issuer` puts a
signature behind a statement about `subject`. Three species, one frame, one
verification path.

### 6.1 The common frame

Every attestation is a map carrying `kind` (text: `"capability"`,
`"testimony"`, or `"membership"`), `issuer` (32-byte key), `subject` (32-byte
key), `exp` (non-negative integer seconds), its species fields (below),
and `sig` (64 bytes). The **statement** is the attestation's canonical
encoding with `sig` (and `memberSig`, where defined) absent; `sig` is the
issuer's signature over the statement. Unknown kinds and unknown fields
are shape errors.

Expiry is law: every attestation carries `exp`, judged against each
verifier's own clock, and an expired attestation proves only what was.
There is no revocation beyond non-renewal.

A verifier MUST reject an attestation unless: the shape is exact, `exp`
has not passed on its clock, `sig` verifies against `issuer` over the
statement, and, for membership, the countersignature check of section 6.4
passes. Validity is all the grammar defines; whether a valid attestation
*suffices* is the receiving gate's judgment, above the waist.

### 6.2 Capability

Species fields: `scope`, a non-empty array of non-empty text strings in
strictly ascending bytewise UTF-8 order (unique by construction), and
`hops`, a non-negative integer delegation budget. Scope entries are
uninterpreted at the waist; their meaning is convention between granter
and grantee.

A **delegation chain** is a sequence of capabilities, root first. A
verifier MUST reject a chain unless every link verifies alone (6.1) and
every non-root link, against its parent: is issued by the parent's `subject`
(`child.issuer = parent.subject`), has `scope` a subset of the parent's, has
`exp` no later than the parent's, and has `hops` strictly less than the
parent's. Delegation only attenuates; a capability with `hops` 0 is not
delegable. Subset is set membership over exact strings; the waist knows
no hierarchy among scope entries.

### 6.3 Testimony

Species field: `body`, a byte string, opaque at the waist. Testimony is
signed experience made portable at the cost of trusting its signer; the
grammar defines no score and no aggregate.

### 6.4 Membership

Species fields: `role` (non-empty text), `epoch` (non-negative integer),
and `memberSig` (64 bytes). `issuer` is the jinn, `subject` the member.

Membership alone is a matched pair. The jinn signs the statement (`sig`,
per 6.1); the member countersigns it (`memberSig`): a signature by `subject`
over the SHA-256 digest of the statement's canonical bytes (section 3.4).
Verification is three checks: the jinn's signature over the statement,
the member's signature over the statement's recomputed digest, and the
recomputation itself, which welds the countersignature to the exact
statement presented. One signature alone is one of the two cheap lies (a
genie draping itself in a jinn's name; a jinn claiming a genie it never
had) and proves nothing: a lone offer is not an attestation and MUST be
rejected at shape.

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
