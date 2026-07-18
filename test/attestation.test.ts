import { beforeAll, describe, expect, it } from "vitest";
import { decodeWire, encodeWire, type WireValue } from "../src/cbor.js";
import { generateKeypair, type Keypair } from "../src/identity.js";
import {
  acceptMembership,
  grantMembership,
  issueCapability,
  issueTestimony,
  parseAttestation,
  verifyAttestation,
  verifyDelegationChain,
  type Capability,
  type Membership,
} from "../src/attestation.js";
import { sealEnvelope, verifyEnvelope, EnvelopeError } from "../src/envelope.js";

let jinn: Keypair; // e.g. Nightmarket
let scribe: Keypair;
let helper: Keypair;
let zar: Keypair; // the attacker

const NOW = 1_800_000_000;
const EXP = NOW + 3600;

beforeAll(async () => {
  jinn = await generateKeypair();
  scribe = await generateKeypair();
  helper = await generateKeypair();
  zar = await generateKeypair();
});

describe("capability", () => {
  it("issues and verifies", async () => {
    const cap = await issueCapability({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      scope: ["orders/place", "orders/read"],
      hops: 1,
    });
    await verifyAttestation(cap, { now: NOW });
    expect(cap.issuer).toEqual(jinn.publicKey);
  });

  it("rejects an expired capability on the verifier's clock", async () => {
    const cap = await issueCapability({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      scope: ["orders/read"],
      hops: 0,
    });
    await expect(verifyAttestation(cap, { now: EXP + 1 })).rejects.toThrow("expired");
  });

  it("rejects a tampered scope (signature fails)", async () => {
    const cap = await issueCapability({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      scope: ["orders/read"],
      hops: 0,
    });
    const widened = { ...cap, scope: ["orders/place", "orders/read"] };
    await expect(verifyAttestation(widened, { now: NOW })).rejects.toThrow(
      "issuer signature does not verify",
    );
  });

  it("enforces scope form: non-empty, sorted, unique", async () => {
    const base = { secretKey: jinn.secretKey, subject: scribe.publicKey, exp: EXP, hops: 0 };
    await expect(issueCapability({ ...base, scope: [] })).rejects.toThrow("non-empty");
    await expect(issueCapability({ ...base, scope: ["b", "a"] })).rejects.toThrow("ascending");
    await expect(issueCapability({ ...base, scope: ["a", "a"] })).rejects.toThrow("ascending");
    await expect(issueCapability({ ...base, scope: [""] })).rejects.toThrow("non-empty text");
  });
});

describe("delegation chains", () => {
  async function chainOf(childOverrides: Partial<Capability> = {}): Promise<Capability[]> {
    const root = await issueCapability({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      scope: ["orders/place", "orders/read"],
      hops: 1,
    });
    const child = await issueCapability({
      secretKey: scribe.secretKey,
      subject: helper.publicKey,
      exp: EXP - 600,
      scope: ["orders/read"],
      hops: 0,
      ...childOverrides,
    });
    return [root, child];
  }

  it("accepts a valid attenuating chain and reports the effective grant", async () => {
    const grant = await verifyDelegationChain(await chainOf(), { now: NOW });
    expect(grant.issuer).toEqual(jinn.publicKey);
    expect(grant.subject).toEqual(helper.publicKey);
    expect(grant.scope).toEqual(["orders/read"]);
    expect(grant.hops).toBe(0);
  });

  it("rejects scope widening", async () => {
    const chain = await chainOf({
      ...(await issueCapability({
        secretKey: scribe.secretKey,
        subject: helper.publicKey,
        exp: EXP - 600,
        scope: ["orders/delete"],
        hops: 0,
      })),
    });
    await expect(verifyDelegationChain(chain, { now: NOW })).rejects.toThrow("widens scope");
  });

  it("rejects expiry extension", async () => {
    const chain = await chainOf(
      await issueCapability({
        secretKey: scribe.secretKey,
        subject: helper.publicKey,
        exp: EXP + 600,
        scope: ["orders/read"],
        hops: 0,
      }),
    );
    await expect(verifyDelegationChain(chain, { now: NOW })).rejects.toThrow("extends expiry");
  });

  it("rejects non-shrinking hops (root hops 0 means not delegable)", async () => {
    const chain = await chainOf(
      await issueCapability({
        secretKey: scribe.secretKey,
        subject: helper.publicKey,
        exp: EXP - 600,
        scope: ["orders/read"],
        hops: 1,
      }),
    );
    await expect(verifyDelegationChain(chain, { now: NOW })).rejects.toThrow("shrink hops");
  });

  it("rejects a link issued by a stranger to the chain", async () => {
    const [root] = await chainOf();
    const forged = await issueCapability({
      secretKey: zar.secretKey, // not the previous subject
      subject: helper.publicKey,
      exp: EXP - 600,
      scope: ["orders/read"],
      hops: 0,
    });
    await expect(verifyDelegationChain([root!, forged], { now: NOW })).rejects.toThrow(
      "not issued by the previous subject",
    );
  });

  it("rejects a chain with an expired middle link", async () => {
    const chain = await chainOf();
    await expect(verifyDelegationChain(chain, { now: EXP - 300 })).rejects.toThrow("expired");
  });
});

describe("testimony", () => {
  it("round-trips through wire bytes", async () => {
    const t = await issueTestimony({
      secretKey: zar.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      body: new TextEncoder().encode("delivered on time, twice"),
    });
    const decoded = parseAttestation(decodeWire(encodeWire(t as unknown as WireValue)));
    await verifyAttestation(decoded, { now: NOW });
    expect(decoded).toEqual(t);
  });
});

describe("membership pair", () => {
  async function pair(): Promise<Membership> {
    const offer = await grantMembership({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      role: "scribe",
      epoch: 1,
      exp: EXP,
    });
    return acceptMembership(offer, scribe.secretKey);
  }

  it("grant, accept, verify: the three checks pass", async () => {
    await verifyAttestation(await pair(), { now: NOW });
  });

  it("cheap lie 1: a stranger cannot forge the jinn's half", async () => {
    // Zar drapes himself in the jinn's name: builds a statement with
    // issuer = jinn but can only sign with his own key.
    const forged = await grantMembership({
      secretKey: zar.secretKey,
      issuer: jinn.publicKey,
      subject: zar.publicKey,
      role: "scribe",
      epoch: 1,
      exp: EXP,
    });
    await expect(acceptMembership(forged, zar.secretKey)).rejects.toThrow(
      "offer signature does not verify",
    );
  });

  it("cheap lie 2: a jinn cannot claim a member who never countersigned", async () => {
    const offer = await grantMembership({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey, // the celebrated genie, who never agreed
      role: "scribe",
      epoch: 1,
      exp: EXP,
    });
    // The jinn forges a countersignature with a key it controls.
    const fake = await acceptMembership(
      { ...offer, subject: zar.publicKey },
      zar.secretKey,
    ).catch(() => null);
    expect(fake).toBeNull(); // subject was inside the signed statement: offer sig broke

    // Presenting the bare offer as if it were a pair fails shape checks.
    expect(() => parseAttestation(offer as unknown as WireValue)).toThrow("missing field: memberSig");
  });

  it("re-pairing: a countersignature cannot be moved to a different statement", async () => {
    const scribePair = await pair();
    const treasurerOffer = await grantMembership({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      role: "treasurer",
      epoch: 1,
      exp: EXP,
    });
    const franken: Membership = {
      ...treasurerOffer,
      memberSig: scribePair.memberSig, // Scribe's acceptance of "scribe"
    };
    await expect(verifyAttestation(franken, { now: NOW })).rejects.toThrow(
      "member countersignature does not verify",
    );
  });

  it("a member refuses to countersign an offer addressed to someone else", async () => {
    const offer = await grantMembership({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      role: "scribe",
      epoch: 1,
      exp: EXP,
    });
    await expect(acceptMembership(offer, zar.secretKey)).rejects.toThrow(
      "not addressed to this key",
    );
  });

  it("membership expires like everything else: a heartbeat, not a tattoo", async () => {
    await expect(verifyAttestation(await pair(), { now: EXP + 1 })).rejects.toThrow("expired");
  });
});

describe("presents: attestations inside envelopes", () => {
  it("carries a membership pair to a verifier and back out", async () => {
    const offer = await grantMembership({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      role: "scribe",
      epoch: 1,
      exp: EXP,
    });
    const membership = await acceptMembership(offer, scribe.secretKey);

    const bytes = await sealEnvelope({
      secretKey: scribe.secretKey,
      payload: new Uint8Array([1]),
      aud: zar.publicKey,
      presents: [membership],
      timestamp: NOW,
    });
    const envelope = await verifyEnvelope(bytes, { recipient: zar.publicKey });

    expect(envelope.presents).toHaveLength(1);
    const presented = envelope.presents![0]!;
    expect(presented.kind).toBe("membership");
    // Presenter and subject match: the standing belongs to the sender.
    expect(envelope.from).toEqual(presented.subject);
    await verifyAttestation(presented, { now: NOW });
  });

  it("rejects garbage in presents at both ends", async () => {
    const bad = { kind: "membership", issuer: jinn.publicKey } as never;
    await expect(
      sealEnvelope({ secretKey: scribe.secretKey, payload: new Uint8Array(), presents: [bad], timestamp: NOW }),
    ).rejects.toThrow(EnvelopeError);

    // Hand-built envelope bytes with a non-attestation in presents.
    const sealed = await sealEnvelope({ secretKey: scribe.secretKey, payload: new Uint8Array(), timestamp: NOW });
    const map = decodeWire(sealed) as { [key: string]: WireValue };
    map.presents = [{ kind: "membership" }];
    await expect(verifyEnvelope(encodeWire(map))).rejects.toThrow("invalid attestation in presents");
  });

  it("rejects an empty presents array", async () => {
    await expect(
      sealEnvelope({ secretKey: scribe.secretKey, payload: new Uint8Array(), presents: [], timestamp: NOW }),
    ).rejects.toThrow("non-empty");
  });

  it("an envelope's signature covers its presents (tamper breaks it)", async () => {
    const cap = await issueCapability({
      secretKey: jinn.secretKey,
      subject: scribe.publicKey,
      exp: EXP,
      scope: ["orders/read"],
      hops: 0,
    });
    const sealed = await sealEnvelope({
      secretKey: scribe.secretKey,
      payload: new Uint8Array(),
      presents: [cap],
      timestamp: NOW,
    });
    const map = decodeWire(sealed) as { [key: string]: WireValue };
    const presented = (map.presents as WireValue[])[0] as { [key: string]: WireValue };
    presented.exp = EXP + 999;
    await expect(verifyEnvelope(encodeWire(map))).rejects.toThrow("signature does not verify");
  });
});

describe("parseAttestation strictness", () => {
  it("rejects unknown kinds and unknown fields", () => {
    expect(() => parseAttestation({ kind: "licence" })).toThrow("unknown attestation kind");
    expect(() =>
      parseAttestation({
        kind: "testimony",
        issuer: new Uint8Array(33).fill(1),
        subject: new Uint8Array(33).fill(1),
        exp: 1,
        body: new Uint8Array(),
        sig: new Uint8Array(64),
        extra: 1,
      }),
    ).toThrow("unknown field: extra");
  });
});
