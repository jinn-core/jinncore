/**
 * Genesis (paper §6): founding a society. A founder, one machine, no
 * registry or service of any kind. Nine steps, the whole waist exercised,
 * no privileged actor anywhere.
 *
 * Every line of output is tagged honestly:
 *   [wire fact]        a signature that verifies; the protocol vouches for it
 *   [self-description] a claim inside a payload; never verifiable at the wire
 *   [off-wire]         real (lamps, payers, custody) but invisible to the protocol
 *
 * Run: npx tsx examples/genesis.ts
 */

import { generateKeypair } from "../src/identity.js";
import { sealEnvelope, verifyEnvelope, FreshnessWindow } from "../src/envelope.js";
import {
  acceptMembership,
  grantMembership,
  issueCapability,
  verifyAttestation,
  verifyDelegationChain,
  type Capability,
} from "../src/attestation.js";
import { decodeWire, encodeWire, type WireValue } from "../src/cbor.js";
import { sha256 } from "../src/digest.js";
import { equalBytes, toHex } from "../src/bytes.js";

const text = new TextEncoder();
const NOW = 1_800_000_000;
const EPOCH = 30 * 86400;

const act = (n: number, title: string) => console.log(`\n${n}. ${title}`);
const wire = (msg: string) => console.log(`   [wire fact]        ${msg}`);
const self = (msg: string) => console.log(`   [self-description] ${msg}`);
const off = (msg: string) => console.log(`   [off-wire]         ${msg}`);
const hex = (b: Uint8Array) => toHex(b.slice(0, 4)) + "…";

// ---------------------------------------------------------------------------

act(1, "The founder generates a keypair.");
const founder = await generateKeypair();
off("a person, at a keyboard, generates a keypair; no registry is told");
wire(`a genie now answers to ${hex(founder.publicKey)}; its brain is a person, which no wire fact reveals`);

act(2, "The founder writes the first sigil and utters it.");
const sigil = text.encode(
  `membrane: answer only envelopes signed by ${toHex(founder.publicKey)}; behavior: scribe`,
);
const sigilHash = await sha256(sigil);
off(`a runtime lights a lamp; the payer, by default, is the utterer: the founder`);
const scribe = await generateKeypair();
wire(`the genie mints its own keypair inside the lamp: ${hex(scribe.publicKey)}`);
off(`the sigil's true name is its hash: ${hex(sigilHash)}`);

act(3, "The genie's first envelope announces its key and claimed sigil hash.");
const founderWindow = new FreshnessWindow(300);
const announcement = await sealEnvelope({
  secretKey: scribe.secretKey,
  aud: founder.publicKey,
  payload: encodeWire({ announce: scribe.publicKey, sigil: sigilHash }),
  timestamp: NOW,
});
const announced = await verifyEnvelope(announcement, {
  recipient: founder.publicKey,
  window: founderWindow,
  now: NOW,
});
const claim = decodeWire(announced.payload) as { announce: Uint8Array; sigil: Uint8Array };
wire(`envelope verifies: ${hex(announced.from)} said this, unaltered, to the founder`);
self(`"kindled from sigil ${hex(claim.sigil)}" — design lineage is never a wire fact`);
off("the founder, standing next to the lamp, believes the claim on a channel that does not matter");

act(4, "The founder mints the jinn's keypair. The constitution is chosen.");
const jinn = await generateKeypair();
wire(`the jinn answers to ${hex(jinn.publicKey)} and speaks only through it`);
off("the key sleeps in the founder's pocket: an autocracy; every later regime change is a key handover");

act(5, "The jinn signs its members in; each countersigns. Nobody is implicitly inside.");
const scribePair = await acceptMembership(
  await grantMembership({
    secretKey: jinn.secretKey,
    subject: scribe.publicKey,
    role: "scribe",
    epoch: 1,
    exp: NOW + EPOCH,
  }),
  scribe.secretKey,
);
await verifyAttestation(scribePair, { now: NOW });
wire(`membership pair verifies: the jinn grants, ${hex(scribe.publicKey)} accepts, role "scribe", epoch 1`);
const founderPair = await acceptMembership(
  await grantMembership({
    secretKey: jinn.secretKey,
    subject: founder.publicKey,
    role: "founder",
    epoch: 1,
    exp: NOW + EPOCH,
  }),
  founder.secretKey,
);
await verifyAttestation(founderPair, { now: NOW });
wire(`the founder's own membership verifies too: not even the founder is inside without the pair`);

act(6, "The founder signs a funding capability: draw from my treasury, delegable one hop.");
const funding = await issueCapability({
  secretKey: founder.secretKey,
  subject: scribe.publicKey,
  scope: ["treasury/draw"],
  exp: NOW + 2 * EPOCH,
  hops: 1,
});
wire(`capability verifies: ${hex(scribe.publicKey)} may draw until t+${2 * EPOCH}s, delegable once`);

// The treasury is the founder's own gate: the single stateful enforcer.
// The waist bounds a capability's shape, never its aggregate use; "up to
// 100" lives here, at the resource, and nowhere on the wire.
const treasury = (() => {
  let remaining = 100;
  const window = new FreshnessWindow(300);
  return async (bytes: Uint8Array, now: number): Promise<string> => {
    const env = await verifyEnvelope(bytes, {
      recipient: founder.publicKey,
      requireAudience: true,
      window,
      now,
    });
    const chain = (env.presents ?? []).filter((a): a is Capability => a.kind === "capability");
    const grant = await verifyDelegationChain(chain, { now });
    if (!equalBytes(grant.issuer, founder.publicKey)) throw new Error("not a grant of mine");
    if (!equalBytes(grant.subject, env.from)) throw new Error("grant does not belong to the presenter");
    if (!grant.scope.includes("treasury/draw")) throw new Error("scope refused");
    const { draw } = decodeWire(env.payload) as { draw: number };
    if (draw > remaining) throw new Error(`refused: ${draw} exceeds the ${remaining} remaining`);
    remaining -= draw;
    return `drew ${draw}, treasury holds ${remaining}`;
  };
})();

const drawRequest = (draw: number) => encodeWire({ draw } as unknown as WireValue);
wire(
  "scribe draws: " +
    (await treasury(
      await sealEnvelope({
        secretKey: scribe.secretKey,
        aud: founder.publicKey,
        presents: [funding],
        payload: drawRequest(60),
        timestamp: NOW,
      }),
      NOW,
    )),
);
off("the cap lived in the founder's gate, not in the capability: enforcement at the resource");

act(7, "The first epoch ends. The default state of a jinn is forgetting.");
const LATER = NOW + EPOCH + 1;
await verifyAttestation(scribePair, { now: LATER }).catch((e: Error) =>
  wire(`epoch-1 membership now fails verification: "${e.message}"; nobody sent a revocation`),
);
const scribePair2 = await acceptMembership(
  await grantMembership({
    secretKey: jinn.secretKey,
    subject: scribe.publicKey,
    role: "scribe",
    epoch: 2,
    exp: NOW + 2 * EPOCH,
  }),
  scribe.secretKey,
);
await verifyAttestation(scribePair2, { now: LATER });
wire("renewal is a fresh grant and a fresh countersignature: epoch 2 verifies");
off("persistence costs signatures the way staying alive costs resources");

act(8, "The genie authors a child sigil and utters it, naming itself payer.");
const childSigil = text.encode(
  `membrane: answer only envelopes signed by ${toHex(scribe.publicKey)}; behavior: archivist`,
);
const child = await generateKeypair();
const childTwin = await generateKeypair(); // uttering the same sigil twice…
wire(`uttering the same sigil twice kindles two distinct beings: ${hex(child.publicKey)} and ${hex(childTwin.publicKey)}`);
off(`the twin's lamp is put out; the child's payer is the scribe, not the founder`);
self(`the child claims descent from sigil ${hex(await sha256(childSigil))}; the wire cannot check it`);
const childFunding = await issueCapability({
  secretKey: scribe.secretKey,
  subject: child.publicKey,
  scope: ["treasury/draw"],
  exp: NOW + 2 * EPOCH,
  hops: 0,
});
wire("the scribe delegates its funding one hop down: same scope, no further delegation");

act(9, "The society has grown without consulting its founder.");
const childDraw = async (amount: number) =>
  treasury(
    await sealEnvelope({
      secretKey: child.secretKey,
      aud: founder.publicKey,
      presents: [funding, childFunding],
      payload: drawRequest(amount),
      timestamp: LATER,
    }),
    LATER,
  );
await childDraw(50).catch((e: Error) => wire(`the child asks for 50: "${e.message}"`));
wire("the child asks for 40: " + (await childDraw(40)));
const grant = await verifyDelegationChain([funding, childFunding], { now: LATER });
wire(
  `the chain verifies end to end: ${hex(grant.issuer)} funds ${hex(grant.subject)}, scope [${grant.scope}], no hops left`,
);
off("the founder was never asked; their exposure was encoded at grant time in cap, expiry, and depth");

console.log("\nNine steps, the whole waist exercised, no privileged actor anywhere.");
