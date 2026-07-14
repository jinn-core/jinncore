import { beforeAll, describe, expect, it } from "vitest";
import { decodeWire, encodeWire, type WireValue } from "../src/cbor.js";
import { generateKeypair, type Keypair } from "../src/identity.js";
import { EnvelopeError, FreshnessWindow, sealEnvelope, verifyEnvelope } from "../src/envelope.js";

let alice: Keypair;
let bob: Keypair;
let carol: Keypair;

const NOW = 1_800_000_000;
const NONCE = new Uint8Array(16).fill(7);
const PAYLOAD = new TextEncoder().encode("buy one cake");

beforeAll(async () => {
  alice = await generateKeypair();
  bob = await generateKeypair();
  carol = await generateKeypair();
});

function sealed(overrides: object = {}) {
  return sealEnvelope({
    secretKey: alice.secretKey,
    payload: PAYLOAD,
    aud: bob.publicKey,
    timestamp: NOW,
    nonce: NONCE,
    ...overrides,
  });
}

/** Decode, apply a mutation to the envelope map, re-encode. */
async function tampered(mutate: (envelope: { [key: string]: WireValue }) => void): Promise<Uint8Array> {
  const envelope = decodeWire(await sealed()) as { [key: string]: WireValue };
  mutate(envelope);
  return encodeWire(envelope);
}

describe("seal and verify", () => {
  it("round-trips a directed envelope", async () => {
    const envelope = await verifyEnvelope(await sealed(), { recipient: bob.publicKey });
    expect(envelope.from).toEqual(alice.publicKey);
    expect(envelope.aud).toEqual(bob.publicKey);
    expect(envelope.payload).toEqual(PAYLOAD);
    expect(envelope.fresh).toEqual({ t: NOW, n: NONCE });
  });

  it("round-trips a public envelope (no aud)", async () => {
    const bytes = await sealEnvelope({ secretKey: alice.secretKey, payload: PAYLOAD, timestamp: NOW, nonce: NONCE });
    const envelope = await verifyEnvelope(bytes, { recipient: bob.publicKey });
    expect(envelope.aud).toBeUndefined();
  });

  it("is deterministic: same inputs, identical bytes", async () => {
    expect(await sealed()).toEqual(await sealed());
  });

  it("derives from when omitted and rejects a forged from", async () => {
    const envelope = await verifyEnvelope(await sealed({ from: undefined }), {});
    expect(envelope.from).toEqual(alice.publicKey);
    // Signed with alice's key but claiming carol's name: signature must fail.
    await expect(verifyEnvelope(await sealed({ from: carol.publicKey }))).rejects.toThrow(
      "signature does not verify",
    );
  });
});

describe("tampering", () => {
  const mutations: Array<[string, (envelope: { [key: string]: WireValue }) => void]> = [
    ["payload", (e) => { (e.payload as Uint8Array)[0]! ^= 1; }],
    ["audience", (e) => { e.aud = carol.publicKey; }],
    ["sender", (e) => { e.from = carol.publicKey; }],
    ["timestamp", (e) => { (e.fresh as { t: number }).t = NOW + 1; }],
    ["nonce", (e) => { ((e.fresh as { n: Uint8Array }).n)[0]! ^= 1; }],
  ];
  for (const [label, mutate] of mutations) {
    it(`rejects a tampered ${label}`, async () => {
      await expect(verifyEnvelope(await tampered(mutate))).rejects.toThrow(EnvelopeError);
    });
  }

  it("rejects a signature moved onto different bytes", async () => {
    const a = decodeWire(await sealed()) as { [key: string]: WireValue };
    const b = decodeWire(await sealed({ payload: new Uint8Array([9]) })) as { [key: string]: WireValue };
    b.sig = a.sig;
    await expect(verifyEnvelope(encodeWire(b))).rejects.toThrow("signature does not verify");
  });
});

describe("shape", () => {
  it("rejects non-canonical bytes", async () => {
    const bytes = await sealed();
    await expect(verifyEnvelope(new Uint8Array([...bytes, 0]))).rejects.toThrow("not canonical");
  });

  it("rejects unknown fields", async () => {
    await expect(verifyEnvelope(await tampered((e) => { e.extra = 1; }))).rejects.toThrow("unknown field");
  });

  it("rejects missing fields", async () => {
    await expect(verifyEnvelope(await tampered((e) => { delete e.fresh; }))).rejects.toThrow("missing field");
  });

  it("rejects a wrong wire version", async () => {
    await expect(verifyEnvelope(await tampered((e) => { e.v = 2; }))).rejects.toThrow("unsupported wire version");
    await expect(verifyEnvelope(await tampered((e) => { e.v = 0; }))).rejects.toThrow("unsupported wire version");
  });

  it("rejects malformed keys and nonces", async () => {
    await expect(verifyEnvelope(await tampered((e) => { e.from = new Uint8Array(31); }))).rejects.toThrow("32-byte key");
    await expect(verifyEnvelope(await tampered((e) => { (e.fresh as { n: WireValue }).n = new Uint8Array(4); }))).rejects.toThrow("fresh.n");
    await expect(verifyEnvelope(await tampered((e) => { (e.fresh as { t: WireValue }).t = -5; }))).rejects.toThrow("fresh.t");
  });

  it("rejects a non-map envelope", async () => {
    await expect(verifyEnvelope(encodeWire([1, 2, 3]))).rejects.toThrow("envelope must be a map");
  });
});

describe("audience gate", () => {
  it("rejects an envelope addressed to someone else (reflection)", async () => {
    await expect(verifyEnvelope(await sealed(), { recipient: carol.publicKey })).rejects.toThrow(
      "different audience",
    );
  });

  it("rejects public envelopes when the verifier demands an audience", async () => {
    const bytes = await sealEnvelope({ secretKey: alice.secretKey, payload: PAYLOAD, timestamp: NOW, nonce: NONCE });
    await expect(verifyEnvelope(bytes, { requireAudience: true })).rejects.toThrow("audience required");
  });
});

describe("freshness gate", () => {
  it("accepts once, rejects the replay", async () => {
    const window = new FreshnessWindow(300);
    const bytes = await sealed();
    await verifyEnvelope(bytes, { window, now: NOW + 10 });
    await expect(verifyEnvelope(bytes, { window, now: NOW + 20 })).rejects.toThrow("already seen");
  });

  it("rejects markers outside the verifier's tolerance, both stale and future", async () => {
    const window = new FreshnessWindow(300);
    await expect(verifyEnvelope(await sealed(), { window, now: NOW + 301 })).rejects.toThrow("outside tolerance");
    await expect(verifyEnvelope(await sealed(), { window, now: NOW - 301 })).rejects.toThrow("outside tolerance");
  });

  it("tolerance is sovereign: another verifier may be stricter", async () => {
    const strict = new FreshnessWindow(5);
    await expect(verifyEnvelope(await sealed(), { window: strict, now: NOW + 6 })).rejects.toThrow("outside tolerance");
  });

  it("distinct nonces at the same second are distinct envelopes, not replays", async () => {
    const window = new FreshnessWindow(300);
    await verifyEnvelope(await sealed(), { window, now: NOW });
    await verifyEnvelope(await sealed({ nonce: new Uint8Array(16).fill(8) }), { window, now: NOW });
  });

  it("forgets markers that have aged out of the window", async () => {
    const window = new FreshnessWindow(300);
    const bytes = await sealed();
    await verifyEnvelope(bytes, { window, now: NOW });
    // 400s later the marker is outside tolerance anyway; the window must
    // also have pruned it rather than remembering forever.
    await expect(verifyEnvelope(bytes, { window, now: NOW + 400 })).rejects.toThrow("outside tolerance");
    expect((window as unknown as { seen: Map<string, number> }).seen.size).toBe(0);
  });
});
