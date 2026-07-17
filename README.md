# jinncore

The core library of **Jinn**, a protocol for societies of sovereign
agents. A participant's name is a key it alone holds, its messages
authenticate themselves over any channel, and its standing travels as
signed, expiring attestations. No registry, no platform, no ledger:
security lives in what you grant, never in what a peer promises.

The theory is the paper at [jinncore.org](https://jinncore.org). This
package is its first artifact: the wire grammar as spec, reference
implementation, and conformance vectors, plus a friendly actor layer on
top.

## Install

```
npm install jinncore
```

## Quickstart

```ts
import { createGenie } from "jinncore";

const alice = await createGenie();   // mints its own keypair; the public key is its name
const bob = await createGenie();

const letter = await alice.seal({ to: bob, payload: "hello" });
const envelope = await bob.open(letter);   // verified, or it throws

console.log(envelope.text());        // "hello"
```

`seal` writes, signs, and closes; the bytes can travel HTTP, a queue, a
chat message, or a QR code, and verify identically wherever they arrive.
`open` checks the signature, that the envelope is addressed to you, replay
against your own window, and the validity of any presented standing.

A society, in a few more lines:

```ts
import { createJinn } from "jinncore";

const guild = await createJinn();
const offer = await guild.admit(alice, { role: "scribe", ttl: 30 * 86400 });
const membership = await alice.accept(offer);   // countersigned: only the pair proves belonging

// alice proves her standing to anyone:
await alice.seal({ to: bob, payload: "…", presents: [membership] });
```

## Two layers, one package

- **`jinncore`** (root) — the actor layer: `createGenie` / `createJinn`,
  `seal`/`open`, `grant`/`delegate`/`testify`, `admit`/`accept`. Safe
  defaults throughout: grants are short-lived unless you say otherwise,
  delegation cannot widen, opened envelopes have their cargo verified.
- **`jinncore/wire`** — the primitives, mirroring [SPEC.md](SPEC.md)
  exactly: canonical serialization (`encodeWire`/`decodeWire`), identity,
  `sealEnvelope`/`verifyEnvelope`, the attestation grammar. This is the
  layer other-language implementations port.

## What's in the repository

| path | what it is |
|---|---|
| [SPEC.md](SPEC.md) | the wire grammar: normative, versioned |
| `src/` | the reference implementation (TypeScript, one dependency: `@noble/ed25519`) |
| [test-vectors/](test-vectors/) | language-neutral conformance vectors; the conformance surface is these files, not this code |
| `examples/` | `quickstart.ts` and `society.ts` (actor layer); `wire/` for the paper's constructions in primitives voice |
| `examples/apps/` | small real programs: `courier` (envelopes over HTTP, persistent identity), `vault` (a capability-gated service), `escrow` (an atomic swap between distrusting parties) |

Run any example or app with `npx tsx <path>`.

## Deliberately absent

The same discipline that shapes the paper shapes this package. Below the
waist is never mandated: no runtime, no key custody beyond "the caller
holds the bytes," no lamp mechanics. Above the waist is never decided: no
transport, no discovery, no directory, no reputation scores, no message
loop. A `Genie` object is the protocol half of a genie: its name, voice,
and gate; you supply the brain (your code) and the lamp (the process you
run it in).

Envelopes sign; they do not encrypt. Confidentiality is a payload-level
convention or a channel property, by your choice.

## Status

Version 0.0.x: unstable, pre-release. The three mandates (identity,
envelope, attestation) are normative in the spec, implemented, and
vectored; the API is settling. Stability promises begin at 0.1.0, per the
spec's change discipline.

## Vocabulary

Sigil, genie, lamp, body, jinn: defined once, in the paper's section 2,
and used here without redefinition.
