/**
 * Envelope (SPEC.md §5): the only object the protocol puts on a wire.
 *
 * seal() builds and signs; verify() strict-decodes, checks shape,
 * signature, audience, and freshness. The signature covers the canonical
 * encoding of the envelope with the `sig` entry absent, so what travels
 * is what was signed.
 */

import { decode, encode, type WireValue } from "./cbor.js";
import { equalBytes, toHex } from "./bytes.js";
import { isBytes, isPlainMap, requireKeys } from "./shape.js";
import {
  AttestationError,
  parseAttestation,
  type Attestation,
} from "./attestation.js";
import {
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  publicKeyOf,
  sign,
  verifySignature,
} from "./identity.js";

export const WIRE_VERSION = 1;
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
  /** Attestations the sender chooses to present. */
  presents?: Attestation[];
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
  /** Attestations to present; omit rather than passing an empty array. */
  presents?: Attestation[];
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
  if (envelope.presents !== undefined) {
    body.presents = envelope.presents as unknown as WireValue;
  }
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

  if (options.presents !== undefined) {
    if (!Array.isArray(options.presents) || options.presents.length === 0) {
      throw new EnvelopeError("presents must be a non-empty array; omit it instead");
    }
    for (const att of options.presents) {
      try {
        parseAttestation(att as unknown as WireValue);
      } catch (error) {
        throw new EnvelopeError(`invalid attestation in presents: ${(error as Error).message}`);
      }
    }
  }

  const body = envelopeBody({
    v: WIRE_VERSION,
    from,
    fresh: { t, n },
    payload: options.payload,
    ...(options.aud !== undefined && { aud: options.aud }),
    ...(options.presents !== undefined && { presents: options.presents }),
  });
  const sig = await sign(encode(body), options.secretKey);
  return encode({ ...body, sig });
}

// --- verification -----------------------------------------------------

/** Parse and shape-check envelope bytes. No signature or policy checks. */
function parseEnvelope(bytes: Uint8Array): Envelope {
  let value: WireValue;
  try {
    value = decode(bytes);
  } catch (error) {
    throw new EnvelopeError(`not canonical wire bytes: ${(error as Error).message}`);
  }
  if (!isPlainMap(value)) throw new EnvelopeError("envelope must be a map");
  requireKeys(value, ["v", "from", "fresh", "payload", "sig"], ["aud", "presents"], EnvelopeError);

  if (value.v !== WIRE_VERSION) throw new EnvelopeError(`unsupported wire version: ${String(value.v)}`);
  if (!isBytes(value.from, PUBLIC_KEY_LENGTH)) throw new EnvelopeError("from must be a 32-byte key");
  if ("aud" in value && !isBytes(value.aud, PUBLIC_KEY_LENGTH)) {
    throw new EnvelopeError("aud must be a 32-byte key");
  }
  if (!isBytes(value.payload)) throw new EnvelopeError("payload must be a byte string");
  if (!isBytes(value.sig, SIGNATURE_LENGTH)) throw new EnvelopeError("sig must be a 64-byte signature");

  const fresh = value.fresh;
  if (!isPlainMap(fresh)) throw new EnvelopeError("fresh must be a map");
  requireKeys(fresh, ["t", "n"], [], EnvelopeError);
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
  if ("presents" in value) {
    if (!Array.isArray(value.presents) || value.presents.length === 0) {
      throw new EnvelopeError("presents must be a non-empty array");
    }
    try {
      envelope.presents = value.presents.map(parseAttestation);
    } catch (error) {
      if (error instanceof AttestationError) {
        throw new EnvelopeError(`invalid attestation in presents: ${error.message}`);
      }
      throw error;
    }
  }
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
 *
 * Presented attestations are shape-checked only; a valid envelope does not
 * imply valid cargo. Which attestations to demand and whether to believe
 * them is the gate's own policy: run verifyAttestation /
 * verifyDelegationChain per that policy.
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

