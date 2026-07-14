/**
 * Generates the language-neutral conformance vectors (SPEC.md §7) into
 * test-vectors/. Fully deterministic: fixed seed keys, fixed timestamps,
 * fixed nonces; Ed25519 is deterministic, so every byte here is
 * reproducible by any conforming implementation.
 *
 * Run: npm run vectors
 */

import { mkdir, writeFile } from "node:fs/promises";
import { encodeWire, decodeWire, type WireValue } from "../src/cbor.js";
import { publicKeyOf } from "../src/identity.js";
import { sealEnvelope } from "../src/envelope.js";
import {
  acceptMembership,
  grantMembership,
  issueCapability,
  issueTestimony,
  type Capability,
  type Membership,
} from "../src/attestation.js";
import { toHex } from "../src/bytes.js";

const OUT = new URL("../test-vectors/", import.meta.url);
const NOW = 1_800_000_000;
const HOUR = 3600;
const NONCE = new Uint8Array(16).fill(7);
const utf8 = new TextEncoder();

// --- fixed actors ---------------------------------------------------------

const seed = (b: number) => new Uint8Array(32).fill(b);
const founderSecret = seed(1);
const jinnSecret = seed(2);
const scribeSecret = seed(3);
const strangerSecret = seed(4);
const founder = await publicKeyOf(founderSecret);
const jinn = await publicKeyOf(jinnSecret);
const scribe = await publicKeyOf(scribeSecret);
const stranger = await publicKeyOf(strangerSecret);

// --- the JSON convention (documented in test-vectors/README.md) ------------

function toJson(value: WireValue): unknown {
  if (value instanceof Uint8Array) return { $hex: toHex(value) };
  if (typeof value === "bigint") return { $bigint: value.toString() };
  if (Array.isArray(value)) return value.map(toJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toJson(v)]));
  }
  return value;
}
const att = (a: object) => toJson(a as unknown as WireValue);

// --- cbor.json --------------------------------------------------------------

const cborEncode: Array<[WireValue, string]> = [
  [0, "00"], [1, "01"], [10, "0a"], [23, "17"], [24, "1818"], [25, "1819"],
  [100, "1864"], [1000, "1903e8"], [1000000, "1a000f4240"],
  [1000000000000, "1b000000e8d4a51000"], [(1n << 64n) - 1n, "1bffffffffffffffff"],
  [-1, "20"], [-10, "29"], [-100, "3863"], [-1000, "3903e7"],
  [-(1n << 64n), "3bffffffffffffffff"],
  [false, "f4"], [true, "f5"], [null, "f6"],
  ["", "60"], ["a", "6161"], ["IETF", "6449455446"], ['"\\', "62225c"],
  ["ü", "62c3bc"], ["水", "63e6b0b4"],
  [new Uint8Array(), "40"], [new Uint8Array([1, 2, 3, 4]), "4401020304"],
  [[], "80"], [[1, 2, 3], "83010203"], [[1, [2, 3], [4, 5]], "8301820203820405"],
  [{}, "a0"], [{ a: 1, b: [2, 3] }, "a26161016162820203"],
  [["a", { b: "c" }], "826161a161626163"],
  [{ b: 2, a: 1 }, "a2616101616202"],
  [{ aa: 2, a: 1 }, "a261610162616102"],
];

const cborReject: Array<[string, string]> = [
  ["1817", "non-shortest one-byte argument"],
  ["190001", "non-shortest two-byte argument"],
  ["1a00000001", "non-shortest four-byte argument"],
  ["1b0000000000000001", "non-shortest eight-byte argument"],
  ["5f4101ff", "indefinite-length byte string"],
  ["7f6161ff", "indefinite-length text string"],
  ["9f01ff", "indefinite-length array"],
  ["bf616101ff", "indefinite-length map"],
  ["f90000", "half-precision float"],
  ["fa00000000", "single-precision float"],
  ["fb0000000000000000", "double-precision float"],
  ["f7", "undefined"],
  ["f818", "unknown simple value"],
  ["c074323031332d30332d32315432303a30343a30305a", "tag"],
  ["a2616201616102", "misordered map keys"],
  ["a2616101616102", "duplicate map keys"],
  ["a1016161", "non-text map key"],
  ["6198", "invalid UTF-8 in text string"],
  ["a161ff01", "invalid UTF-8 in map key"],
  ["0000", "trailing bytes"],
  ["18", "truncated argument"],
  ["4401020304ff", "trailing bytes after byte string"],
  ["440102", "truncated byte string"],
  ["8301", "truncated array"],
  ["1c", "reserved additional information 28"],
  ["", "empty input"],
];

// --- attestations -----------------------------------------------------------

const speak: Capability = await issueCapability({
  secretKey: founderSecret,
  subject: scribe,
  exp: NOW + HOUR,
  scope: ["orders/place", "orders/read"],
  hops: 1,
});
const delegated: Capability = await issueCapability({
  secretKey: scribeSecret,
  subject: stranger,
  exp: NOW + HOUR - 600,
  scope: ["orders/read"],
  hops: 0,
});
const testimony = await issueTestimony({
  secretKey: strangerSecret,
  subject: scribe,
  exp: NOW + HOUR,
  body: utf8.encode("delivered on time, twice"),
});
const offer = await grantMembership({
  secretKey: jinnSecret,
  subject: scribe,
  role: "scribe",
  epoch: 1,
  exp: NOW + HOUR,
});
const membership: Membership = await acceptMembership(offer, scribeSecret);
const treasurerPair = await acceptMembership(
  await grantMembership({
    secretKey: jinnSecret,
    subject: scribe,
    role: "treasurer",
    epoch: 1,
    exp: NOW + HOUR,
  }),
  scribeSecret,
);
const rePaired = { ...treasurerPair, memberSig: membership.memberSig };

const bytesOf = (a: object) => toHex(encodeWire(a as unknown as WireValue));

const attestationVectors = {
  description:
    "Attestation issuance and verification (SPEC.md §6). `bytes` is the canonical encoding of the full attestation map. Verification of `bytes` means: strict-decode, shape-check, then check expiry against `now`, issuer signature over the statement (the map without sig/memberSig), and for membership the countersignature over SHA-256 of the statement.",
  keys: {
    founder: { secret: toHex(founderSecret), public: toHex(founder) },
    jinn: { secret: toHex(jinnSecret), public: toHex(jinn) },
    scribe: { secret: toHex(scribeSecret), public: toHex(scribe) },
    stranger: { secret: toHex(strangerSecret), public: toHex(stranger) },
  },
  issue: [
    { name: "capability", attestation: att(speak), bytes: bytesOf(speak) },
    { name: "delegated capability", attestation: att(delegated), bytes: bytesOf(delegated) },
    { name: "testimony", attestation: att(testimony), bytes: bytesOf(testimony) },
    { name: "membership pair", attestation: att(membership), bytes: bytesOf(membership) },
  ],
  verify: [
    { name: "capability valid", bytes: bytesOf(speak), now: NOW, expect: "ok" },
    { name: "capability expired", bytes: bytesOf(speak), now: NOW + HOUR + 1, expect: "reject", reason: "expired" },
    { name: "membership pair valid", bytes: bytesOf(membership), now: NOW, expect: "ok" },
    { name: "lone offer is not standing", bytes: bytesOf(offer), now: NOW, expect: "reject", reason: "missing memberSig (shape)" },
    { name: "re-paired countersignature", bytes: bytesOf(rePaired), now: NOW, expect: "reject", reason: "countersignature does not verify" },
    { name: "testimony valid", bytes: bytesOf(testimony), now: NOW, expect: "ok" },
  ],
  chains: [
    {
      name: "valid attenuating chain",
      chain: [bytesOf(speak), bytesOf(delegated)],
      now: NOW,
      expect: "ok",
      grant: { issuer: toHex(founder), subject: toHex(stranger), scope: ["orders/read"], exp: NOW + HOUR - 600, hops: 0 },
    },
    {
      name: "scope widening",
      chain: [
        bytesOf(speak),
        bytesOf(await issueCapability({ secretKey: scribeSecret, subject: stranger, exp: NOW + HOUR - 600, scope: ["orders/delete"], hops: 0 })),
      ],
      now: NOW,
      expect: "reject",
      reason: "delegation widens scope",
    },
    {
      name: "expiry extension",
      chain: [
        bytesOf(speak),
        bytesOf(await issueCapability({ secretKey: scribeSecret, subject: stranger, exp: NOW + 2 * HOUR, scope: ["orders/read"], hops: 0 })),
      ],
      now: NOW,
      expect: "reject",
      reason: "delegation extends expiry",
    },
    {
      name: "non-shrinking hops",
      chain: [
        bytesOf(speak),
        bytesOf(await issueCapability({ secretKey: scribeSecret, subject: stranger, exp: NOW + HOUR - 600, scope: ["orders/read"], hops: 1 })),
      ],
      now: NOW,
      expect: "reject",
      reason: "hops must strictly shrink",
    },
    {
      name: "link issued by a stranger to the chain",
      chain: [
        bytesOf(speak),
        bytesOf(await issueCapability({ secretKey: strangerSecret, subject: stranger, exp: NOW + HOUR - 600, scope: ["orders/read"], hops: 0 })),
      ],
      now: NOW,
      expect: "reject",
      reason: "link not issued by previous subject",
    },
  ],
};

// --- envelopes ---------------------------------------------------------------

const publicBytes = await sealEnvelope({
  secretKey: scribeSecret,
  payload: utf8.encode("hello"),
  timestamp: NOW,
  nonce: NONCE,
});
const directedBytes = await sealEnvelope({
  secretKey: scribeSecret,
  aud: founder,
  payload: utf8.encode("who are you?"),
  timestamp: NOW,
  nonce: NONCE,
});
const presentingBytes = await sealEnvelope({
  secretKey: scribeSecret,
  aud: founder,
  presents: [membership],
  payload: utf8.encode("the jinn sent me"),
  timestamp: NOW,
  nonce: NONCE,
});

const tampered = Uint8Array.from(decodeWire(directedBytes) === null ? [] : directedBytes);
tampered[tampered.length - 1]! ^= 1;
const wrongVersion = (() => {
  const map = decodeWire(directedBytes) as { [key: string]: WireValue };
  map.v = 2;
  return encodeWire(map);
})();

const envelopeVectors = {
  description:
    "Envelope sealing and verification (SPEC.md §5). Sealing: sign the canonical map without `sig`, then transmit the canonical map with it. Verify cases: strict-decode, shape, signature over the re-encoded body, audience when the verifier enforces one. Freshness policy is verifier-local state and is deliberately not vectored.",
  keys: attestationVectors.keys,
  seal: [
    {
      name: "public envelope",
      options: { secretKey: toHex(scribeSecret), payload: toHex(utf8.encode("hello")), timestamp: NOW, nonce: toHex(NONCE) },
      bytes: toHex(publicBytes),
    },
    {
      name: "directed envelope",
      options: { secretKey: toHex(scribeSecret), aud: [toHex(founder)], payload: toHex(utf8.encode("who are you?")), timestamp: NOW, nonce: toHex(NONCE) },
      bytes: toHex(directedBytes),
    },
    {
      name: "directed envelope presenting a membership pair",
      options: { secretKey: toHex(scribeSecret), aud: [toHex(founder)], presents: [att(membership)], payload: toHex(utf8.encode("the jinn sent me")), timestamp: NOW, nonce: toHex(NONCE) },
      bytes: toHex(presentingBytes),
    },
  ],
  verify: [
    { name: "directed, correct recipient", bytes: toHex(directedBytes), recipient: toHex(founder), expect: "ok" },
    { name: "reflection: wrong recipient", bytes: toHex(directedBytes), recipient: toHex(stranger), expect: "reject", reason: "addressed to a different audience" },
    { name: "tampered byte", bytes: toHex(tampered), recipient: toHex(founder), expect: "reject", reason: "signature does not verify" },
    { name: "unsupported wire version", bytes: toHex(wrongVersion), recipient: toHex(founder), expect: "reject", reason: "unsupported wire version" },
    { name: "trailing byte", bytes: toHex(directedBytes) + "00", recipient: toHex(founder), expect: "reject", reason: "not canonical" },
    { name: "public envelope where audience is required", bytes: toHex(publicBytes), requireAudience: true, expect: "reject", reason: "audience required" },
    { name: "public envelope accepted when audience not required", bytes: toHex(publicBytes), expect: "ok" },
  ],
};

// --- write -------------------------------------------------------------------

await mkdir(OUT, { recursive: true });
const write = (name: string, data: object) =>
  writeFile(new URL(name, OUT), JSON.stringify(data, null, 2) + "\n");

await write("cbor.json", {
  description:
    "Canonical serialization (SPEC.md §3). `encode`: the value (in the JSON convention of README.md) must encode to exactly `hex`, and `hex` must decode back to it. `reject`: a strict decoder must refuse these bytes.",
  encode: cborEncode.map(([value, hex]) => ({ value: toJson(value), hex })),
  reject: cborReject.map(([hex, reason]) => ({ hex, reason })),
});
await write("envelope.json", envelopeVectors);
await write("attestation.json", attestationVectors);

console.log(`vectors written to ${OUT.pathname}`);
