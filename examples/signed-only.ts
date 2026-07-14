/**
 * The signed-only genie (paper §6): the membrane in one move.
 *
 * Where hello-world's gate was wide open, this genie has one rule: the
 * founder's key passes, and anyone else must present unexpired standing
 * granted by the founder. Everything else gets one identical refusal.
 *
 * What it demonstrates: strangers, replay, reflection, and tampering are
 * all defeated by the mandates plus this single rule, and a friend whose
 * grant has lapsed is refused in exactly the words a stranger hears.
 *
 * Run: npx tsx examples/signed-only.ts
 */

import { generateKeypair } from "../src/identity.js";
import { sealEnvelope, verifyEnvelope, FreshnessWindow, type Envelope } from "../src/envelope.js";
import { issueCapability, verifyAttestation } from "../src/attestation.js";
import { equalBytes, toHex } from "../src/bytes.js";

const text = new TextEncoder();
const NOW = 1_800_000_000;
const HOUR = 3600;

// --- the cast -------------------------------------------------------------

const genie = await generateKeypair();
const founder = await generateKeypair();
const friend = await generateKeypair();
const stranger = await generateKeypair();

// --- the genie's membrane ---------------------------------------------------

const window = new FreshnessWindow(300);

// The whole policy: my founder passes; anyone else needs an unexpired
// "speak" capability granted by my founder to their own key. No exception
// leaks *why* someone was refused beyond what the mandates already reveal.
async function gate(bytes: Uint8Array, now: number): Promise<Envelope> {
  const envelope = await verifyEnvelope(bytes, {
    recipient: genie.publicKey,
    requireAudience: true,
    window,
    now,
  });
  if (equalBytes(envelope.from, founder.publicKey)) return envelope;
  for (const att of envelope.presents ?? []) {
    if (att.kind !== "capability") continue;
    if (!equalBytes(att.issuer, founder.publicKey)) continue;
    if (!equalBytes(att.subject, envelope.from)) continue;
    if (!att.scope.includes("speak")) continue;
    try {
      await verifyAttestation(att, { now });
    } catch {
      continue; // lapsed or forged standing is no standing
    }
    return envelope;
  }
  throw new Error("no standing this gate accepts");
}

async function approach(label: string, bytes: Uint8Array, now: number): Promise<void> {
  try {
    const envelope = await gate(bytes, now);
    console.log(`  accepted: ${label} (from ${hex(envelope.from)})`);
  } catch (error) {
    console.log(`  refused:  ${label} — ${(error as Error).message}`);
  }
}

// --- the encounters ---------------------------------------------------------

console.log(`founder: ${hex(founder.publicKey)}  friend: ${hex(friend.publicKey)}  stranger: ${hex(stranger.publicKey)}\n`);

console.log("1. The founder speaks.");
const fromFounder = await sealEnvelope({
  secretKey: founder.secretKey,
  aud: genie.publicKey,
  payload: text.encode("status?"),
  timestamp: NOW,
});
await approach("founder", fromFounder, NOW);

console.log("\n2. A stranger speaks, with a perfectly valid envelope.");
await approach(
  "stranger",
  await sealEnvelope({
    secretKey: stranger.secretKey,
    aud: genie.publicKey,
    payload: text.encode("status?"),
    timestamp: NOW,
  }),
  NOW,
);

console.log("\n3. Reflection: the founder's envelope to someone else, re-delivered here.");
await approach(
  "reflected founder envelope",
  await sealEnvelope({
    secretKey: founder.secretKey,
    aud: stranger.publicKey, // genuinely the founder's words, but not for this genie
    payload: text.encode("approved"),
    timestamp: NOW,
  }),
  NOW,
);

console.log("\n4. Tampering: the founder's envelope with one payload bit flipped.");
const bent = Uint8Array.from(fromFounder);
bent[bent.length - 1]! ^= 1;
await approach("tampered founder envelope", bent, NOW);

console.log("\n5. Replay: the founder's first envelope, verbatim, again.");
await approach("replayed founder envelope", fromFounder, NOW);

console.log("\n6. A friend arrives, presenting a 'speak' capability granted by the founder.");
const speak = await issueCapability({
  secretKey: founder.secretKey,
  subject: friend.publicKey,
  scope: ["speak"],
  exp: NOW + HOUR,
  hops: 0,
});
await approach(
  "friend (valid grant)",
  await sealEnvelope({
    secretKey: friend.secretKey,
    aud: genie.publicKey,
    presents: [speak],
    payload: text.encode("the founder sent me"),
    timestamp: NOW,
  }),
  NOW,
);

console.log("\n7. Two hours later the same friend, same capability, returns. The grant has lapsed.");
await approach(
  "friend (lapsed grant)",
  await sealEnvelope({
    secretKey: friend.secretKey,
    aud: genie.publicKey,
    presents: [speak],
    payload: text.encode("it's still me"),
    timestamp: NOW + 2 * HOUR,
  }),
  NOW + 2 * HOUR,
);

console.log("\nOne rule at the gate; the mandates do the rest. A lapsed friend and a stranger hear the same sentence.");

function hex(bytes: Uint8Array): string {
  return toHex(bytes.slice(0, 4)) + "…";
}
