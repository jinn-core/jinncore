/**
 * Quickstart: two genies, one verified message.
 *
 * Run: npx tsx examples/quickstart.ts
 */

import { createGenie } from "../src/index.js";

const alice = await createGenie();
const bob = await createGenie();

// Alice seals an envelope: written, signed, closed. The bytes can travel
// any channel at all: HTTP, a queue, a chat message, a QR code.
const letter = await alice.seal({ to: bob, payload: "hello" });

// Bob opens it: signature, addressed-to-me, and replay protection all
// checked. If anything is wrong, open() throws instead of returning.
const envelope = await bob.open(letter);

console.log("from:   ", alice.hex.slice(0, 8) + "…");
console.log("payload:", new TextDecoder().decode(envelope.payload));

// The same bytes a second time is a replay, and bob remembers:
await bob.open(letter).catch((e: Error) => console.log("replay: ", e.message));
