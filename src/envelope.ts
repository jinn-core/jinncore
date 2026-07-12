/**
 * Envelope (SPEC.md §5): the only object the protocol puts on a wire.
 *
 * seal() builds and signs; verify() strict-decodes, checks shape,
 * signature, audience, and freshness. The signature covers the canonical
 * encoding of the envelope with the `sig` entry absent, so what travels
 * is what was signed.
 */

import { decode, encode, type WireValue } from "./cbor.js";
import {
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  publicKeyOf,
  sign,
  verifySignature,
} from "./identity.js";

export const WIRE_VERSION = 0;
export const NONCE_LENGTH_DEFAULT = 16;
export const NONCE_LENGTH_MIN = 8;
export const NONCE_LENGTH_MAX = 32;

export class EnvelopeError extends Error {}

/** The freshness marker: the sender's claimed time and a per-envelope nonce. */
export interface Fresh {
  t: number;
  n: Uint8Array;
}

export interface Envelope {
  v: number;
  from: Uint8Array;
  aud?: Uint8Array;
  fresh: Fresh;
  payload: Uint8Array;
  sig: Uint8Array;
}

export interface SealOptions {
  secretKey: Uint8Array;
  payload: Uint8Array;
  /** Sender's public key; derived from secretKey when omitted. */
  from?: Uint8Array;
  /** Audience commitment; absent means public by construction. */
  aud?: Uint8Array;
  /** Sender-claimed seconds; defaults to the sender's own clock. */
  t?: number;
  /** Per-envelope nonce; defaults to NONCE_LENGTH_DEFAULT random bytes. */
  nonce?: Uint8Array;
}

function envelopeBody(envelope: Omit<Envelope, "sig">): { [key: string]: WireValue } {
  const body: { [key: string]: WireValue } = {
    v: envelope.v,
    from: envelope.from,
    fresh: { t: envelope.fresh.t, n: envelope.fresh.n },
    payload: envelope.payload,
  };
  if (envelope.aud !== undefined) body.aud = envelope.aud;
  return body;
}

/** Build and sign an envelope; returns the wire bytes. */
export async function seal(options: SealOptions): Promise<Uint8Array> {
  const from = options.from ?? (await publicKeyOf(options.secretKey));
  const t = options.t ?? Math.floor(Date.now() / 1000);
  const n = options.nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LENGTH_DEFAULT));

  if (from.length !== PUBLIC_KEY_LENGTH) throw new EnvelopeError("from must be a 32-byte key");
  if (options.aud !== undefined && options.aud.length !== PUBLIC_KEY_LENGTH) {
    throw new EnvelopeError("aud must be a 32-byte key");
  }
  if (!Number.isSafeInteger(t) || t < 0) throw new EnvelopeError("t must be a non-negative integer");
  if (n.length < NONCE_LENGTH_MIN || n.length > NONCE_LENGTH_MAX) {
    throw new EnvelopeError(`nonce must be ${NONCE_LENGTH_MIN}..${NONCE_LENGTH_MAX} bytes`);
  }

  const body = envelopeBody({ v: WIRE_VERSION, from, fresh: { t, n }, payload: options.payload, ...(options.aud !== undefined && { aud: options.aud }) });
  const sig = await sign(encode(body), options.secretKey);
  return encode({ ...body, sig });
}

// --- verification -----------------------------------------------------

function isBytes(value: WireValue | undefined, length?: number): value is Uint8Array {
  return value instanceof Uint8Array && (length === undefined || value.length === length);
}

function isPlainMap(value: WireValue | undefined): value is { [key: string]: WireValue } {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
  );
}

function requireKeys(map: { [key: string]: WireValue }, required: string[], optional: string[]): void {
  const keys = Object.keys(map);
  for (const key of required) {
    if (!keys.includes(key)) throw new EnvelopeError(`missing field: ${key}`);
  }
  for (const key of keys) {
    if (!required.includes(key) && !optional.includes(key)) {
      throw new EnvelopeError(`unknown field: ${key}`);
    }
  }
}

/** Parse and shape-check envelope bytes. No signature or policy checks. */
function parseEnvelope(bytes: Uint8Array): Envelope {
  let value: WireValue;
  try {
    value = decode(bytes);
  } catch (error) {
    throw new EnvelopeError(`not canonical wire bytes: ${(error as Error).message}`);
  }
  if (!isPlainMap(value)) throw new EnvelopeError("envelope must be a map");
  requireKeys(value, ["v", "from", "fresh", "payload", "sig"], ["aud"]);

  if (value.v !== WIRE_VERSION) throw new EnvelopeError(`unsupported wire version: ${String(value.v)}`);
  if (!isBytes(value.from, PUBLIC_KEY_LENGTH)) throw new EnvelopeError("from must be a 32-byte key");
  if ("aud" in value && !isBytes(value.aud, PUBLIC_KEY_LENGTH)) {
    throw new EnvelopeError("aud must be a 32-byte key");
  }
  if (!isBytes(value.payload)) throw new EnvelopeError("payload must be a byte string");
  if (!isBytes(value.sig, SIGNATURE_LENGTH)) throw new EnvelopeError("sig must be a 64-byte signature");

  const fresh = value.fresh;
  if (!isPlainMap(fresh)) throw new EnvelopeError("fresh must be a map");
  requireKeys(fresh, ["t", "n"], []);
  if (typeof fresh.t !== "number" || !Number.isSafeInteger(fresh.t) || fresh.t < 0) {
    throw new EnvelopeError("fresh.t must be a non-negative integer");
  }
  if (!isBytes(fresh.n) || fresh.n.length < NONCE_LENGTH_MIN || fresh.n.length > NONCE_LENGTH_MAX) {
    throw new EnvelopeError(`fresh.n must be ${NONCE_LENGTH_MIN}..${NONCE_LENGTH_MAX} bytes`);
  }

  const envelope: Envelope = {
    v: value.v,
    from: value.from,
    fresh: { t: fresh.t, n: fresh.n },
    payload: value.payload,
    sig: value.sig,
  };
  if ("aud" in value) envelope.aud = value.aud as Uint8Array;
  return envelope;
}

/**
 * Bounded replay memory: remembers freshness markers inside the tolerance
 * window, forgets everything older. One instance per verifier.
 */
export class FreshnessWindow {
  private seen = new Map<string, number>();

  constructor(readonly tolerance: number = 300) {}

  /** Throws if the marker is outside tolerance or already seen. */
  check(from: Uint8Array, fresh: Fresh, now: number): void {
    // Prune before any verdict: memory stays bounded even under a flood
    // of rejected envelopes.
    for (const [key, t] of this.seen) {
      if (now - t > this.tolerance) this.seen.delete(key);
    }
    if (Math.abs(now - fresh.t) > this.tolerance) {
      throw new EnvelopeError("freshness marker outside tolerance");
    }
    const marker = `${toHex(from)}:${toHex(fresh.n)}:${fresh.t}`;
    if (this.seen.has(marker)) throw new EnvelopeError("freshness marker already seen");
    this.seen.set(marker, fresh.t);
  }
}

export interface VerifyOptions {
  /**
   * The verifier's own key. When set, a directed envelope must be
   * addressed to it. Public envelopes (no aud) still pass unless
   * requireAudience is also set.
   */
  recipient?: Uint8Array;
  /** Reject public envelopes outright. */
  requireAudience?: boolean;
  /** Replay and clock policy; freshness is unchecked when omitted. */
  window?: FreshnessWindow;
  /** The verifier's clock, seconds; defaults to this machine's clock. */
  now?: number;
}

/**
 * Verify envelope bytes: canonical decoding, shape, signature, audience,
 * freshness. Returns the envelope on success, throws EnvelopeError on any
 * failure. Judge the sender, ignore the messenger.
 */
export async function verify(bytes: Uint8Array, options: VerifyOptions = {}): Promise<Envelope> {
  const envelope = parseEnvelope(bytes);

  const body = envelopeBody(envelope);
  const signatureValid = await verifySignature(envelope.sig, encode(body), envelope.from);
  if (!signatureValid) throw new EnvelopeError("signature does not verify");

  if (envelope.aud !== undefined) {
    if (options.recipient !== undefined && !equalBytes(envelope.aud, options.recipient)) {
      throw new EnvelopeError("envelope addressed to a different audience");
    }
  } else if (options.requireAudience) {
    throw new EnvelopeError("public envelope rejected: audience required");
  }

  if (options.window) {
    const now = options.now ?? Math.floor(Date.now() / 1000);
    options.window.check(envelope.from, envelope.fresh, now);
  }

  return envelope;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
