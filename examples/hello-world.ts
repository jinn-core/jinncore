/**
 * The hello-world genie (paper §6): the conformance floor.
 *
 * A held key, envelopes, a paid lamp and nothing else is a full citizen.
 * Its gate is wide open on purpose: it answers any valid envelope from
 * anyone, because its answer is worthless. What this demonstrates is that
 * even the most naive citizen gets origin, integrity, replay protection,
 * and tamper-evidence from the mandates alone, with zero policy of its own.
 *
 * Run: npx tsx examples/hello-world.ts
 */

import { mintKeypair } from "../src/identity.js";
import { seal, verify, FreshnessWindow, type Envelope } from "../src/envelope.js";

const text = new TextEncoder();
const untext = new TextDecoder();

// --- the genie ----------------------------------------------------------

// Kindling: the genie mints its own keypair. The public half is its name;
// the secret half never leaves this closure (its lamp).
const genie = await mintKeypair();

// Its entire membrane policy: one replay window. Nothing else.
const window = new FreshnessWindow(300);

// Its entire behavior: verify whatever arrives, answer "hello".
async function helloGenie(bytes: Uint8Array): Promise<Uint8Array> {
  const incoming: Envelope = await verify(bytes, { window }); // throws on anything invalid
  console.log(`  genie: valid envelope from ${hex(incoming.from)}, payload "${untext.decode(incoming.payload)}"`);
  return seal({
    secretKey: genie.secretKey,
    aud: incoming.from,
    payload: text.encode("hello"),
  });
}

// --- a stranger meets it ------------------------------------------------

const stranger = await mintKeypair();
console.log("stranger:", hex(stranger.publicKey));
console.log("genie:   ", hex(genie.publicKey));

console.log("\n1. The stranger sends a public envelope. No prior contact, no standing, no introduction.");
const question = await seal({
  secretKey: stranger.secretKey,
  payload: text.encode("who are you?"),
});
const answer = await helloGenie(question);

console.log("\n2. The stranger verifies the answer: origin and integrity, from the mandates alone.");
const reply = await verify(answer, { recipient: stranger.publicKey });
console.log(`  stranger: "${untext.decode(reply.payload)}" — signed by ${hex(reply.from)}, addressed to me`);

console.log("\n3. A relay replays the stranger's first envelope verbatim. The window remembers.");
await helloGenie(question).catch((e: Error) => console.log(`  genie refuses: ${e.message}`));

console.log("\n4. A relay flips one payload bit in transit. The signature notices.");
const tampered = Uint8Array.from(question);
tampered[tampered.length - 1]! ^= 1;
await helloGenie(tampered).catch((e: Error) => console.log(`  genie refuses: ${e.message}`));

console.log("\nThe floor holds: a key, envelopes, and a paid lamp are a full citizen.");

function hex(bytes: Uint8Array): string {
  return [...bytes.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("") + "…";
}
