/**
 * Re-runs the reference implementation against the emitted conformance
 * vectors, so the vectors can never drift from the code. Run
 * `npm run vectors` after any wire-grammar change, then this suite.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeWire, encodeWire, type WireValue } from "../src/cbor.js";
import { fromHex, toHex } from "../src/bytes.js";
import { sealEnvelope, verifyEnvelope } from "../src/envelope.js";
import {
  parseAttestation,
  verifyAttestation,
  verifyDelegationChain,
  type Attestation,
  type Capability,
} from "../src/attestation.js";

const load = (name: string) =>
  JSON.parse(readFileSync(new URL(`../test-vectors/${name}`, import.meta.url), "utf8"));

/** Inverse of the generator's JSON convention. */
function fromJson(value: unknown): WireValue {
  if (Array.isArray(value)) return value.map(fromJson);
  if (value !== null && typeof value === "object") {
    const record = value as { [key: string]: unknown };
    if (typeof record.$hex === "string" && Object.keys(record).length === 1) {
      return fromHex(record.$hex);
    }
    if (typeof record.$bigint === "string" && Object.keys(record).length === 1) {
      return BigInt(record.$bigint);
    }
    return Object.fromEntries(Object.entries(record).map(([k, v]) => [k, fromJson(v)]));
  }
  return value as WireValue;
}

describe("cbor vectors", () => {
  const vectors = load("cbor.json");
  it("every encode vector round-trips exactly", () => {
    for (const { value, hex } of vectors.encode) {
      expect(toHex(encodeWire(fromJson(value))), hex).toBe(hex);
      expect(toHex(encodeWire(decodeWire(fromHex(hex))))).toBe(hex);
    }
  });
  it("every reject vector is rejected", () => {
    for (const { hex, reason } of vectors.reject) {
      expect(() => decodeWire(fromHex(hex)), reason).toThrow();
    }
  });
});

describe("envelope vectors", () => {
  const vectors = load("envelope.json");
  it("every seal vector reproduces its bytes", async () => {
    for (const { name, options, bytes } of vectors.seal) {
      const sealed = await sealEnvelope({
        secretKey: fromHex(options.secretKey),
        payload: fromHex(options.payload),
        timestamp: options.timestamp,
        nonce: fromHex(options.nonce),
        ...(options.aud && { aud: fromHex(options.aud) }),
        ...(options.presents && {
          presents: options.presents.map((a: unknown) => fromJson(a) as unknown as Attestation),
        }),
      });
      expect(toHex(sealed), name).toBe(bytes);
    }
  });
  it("every verify vector reaches its verdict", async () => {
    for (const { name, bytes, recipient, requireAudience, expect: verdict } of vectors.verify) {
      const run = verifyEnvelope(fromHex(bytes), {
        ...(recipient && { recipient: fromHex(recipient) }),
        ...(requireAudience && { requireAudience }),
      });
      if (verdict === "ok") await expect(run, name).resolves.toBeDefined();
      else await expect(run, name).rejects.toThrow();
    }
  });
});

describe("attestation vectors", () => {
  const vectors = load("attestation.json");
  it("every issue vector reproduces its bytes and parses back", () => {
    for (const { name, attestation, bytes } of vectors.issue) {
      const value = fromJson(attestation);
      expect(toHex(encodeWire(value)), name).toBe(bytes);
      expect(parseAttestation(decodeWire(fromHex(bytes)))).toEqual(value);
    }
  });
  it("every verify vector reaches its verdict", async () => {
    for (const { name, bytes, now, expect: verdict } of vectors.verify) {
      const run = (async () =>
        verifyAttestation(parseAttestation(decodeWire(fromHex(bytes))), { now }))();
      if (verdict === "ok") await expect(run, name).resolves.toBeUndefined();
      else await expect(run, name).rejects.toThrow();
    }
  });
  it("every chain vector reaches its verdict", async () => {
    for (const { name, chain, now, expect: verdict, grant } of vectors.chains) {
      const links = chain.map(
        (hex: string) => parseAttestation(decodeWire(fromHex(hex))) as Capability,
      );
      const run = verifyDelegationChain(links, { now });
      if (verdict === "ok") {
        const result = await run;
        expect(toHex(result.issuer), name).toBe(grant.issuer);
        expect(toHex(result.subject), name).toBe(grant.subject);
        expect(result.scope, name).toEqual(grant.scope);
        expect(result.exp, name).toBe(grant.exp);
        expect(result.hops, name).toBe(grant.hops);
      } else {
        await expect(run, name).rejects.toThrow();
      }
    }
  });
});
