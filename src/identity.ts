/**
 * Identity (SPEC.md §4): a genie's name is a suite-tagged public key it
 * mints for itself at kindling. The first byte names the signature suite;
 * Ed25519 (tag 0x01) is the single mandatory baseline, and a key whose tag
 * a verifier does not implement is rejected at shape: refusal, never
 * negotiation. Secret keys carry the same tag, so a stored keypair is
 * self-describing. Signatures are untagged; their suite is the suite of
 * the key they verify against. Where the secret half sleeps is key
 * custody, below the waist, the caller's business.
 */

import * as ed from "@noble/ed25519";
import { JinncoreError } from "./errors.js";

/** The Ed25519 suite tag: the single mandatory baseline (SPEC.md §4). */
export const SUITE_ED25519 = 0x01;

/** Byte lengths for the Ed25519 baseline; tagged keys carry 1 tag + 32 key bytes. */
export const PUBLIC_KEY_LENGTH = 33;
export const SECRET_KEY_LENGTH = 33;
export const SIGNATURE_LENGTH = 64;

/** A keypair: the public half is the name, the secret half never travels. */
export interface Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Tagged public-key length for a suite tag, or undefined for an unknown suite. */
export function publicKeyLengthOf(suite: number): number | undefined {
  return suite === SUITE_ED25519 ? PUBLIC_KEY_LENGTH : undefined;
}

/** Signature length for a suite tag, or undefined for an unknown suite. */
export function signatureLengthOf(suite: number): number | undefined {
  return suite === SUITE_ED25519 ? SIGNATURE_LENGTH : undefined;
}

/** True iff the bytes are a suite-tagged public key of a suite this build implements. */
export function isTaggedKey(value: unknown): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.length > 0 &&
    publicKeyLengthOf(value[0]!) === value.length
  );
}

function tagged(suite: number, bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length + 1);
  out[0] = suite;
  out.set(bytes, 1);
  return out;
}

function ed25519SecretOf(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length === 0 || secretKey[0] !== SUITE_ED25519) {
    throw new JinncoreError("unknown secret-key suite");
  }
  if (secretKey.length !== SECRET_KEY_LENGTH) {
    throw new JinncoreError("malformed Ed25519 secret key");
  }
  return secretKey.subarray(1);
}

/**
 * Generate a fresh identity. The public key is the name; everything the
 * protocol can ever say about a participant, it says about this key.
 *
 * @example
 * const me = await generateKeypair();
 * console.log(toHex(me.publicKey)); // the name, starting with the suite tag "01"
 */
export async function generateKeypair(): Promise<Keypair> {
  const secret = ed.utils.randomPrivateKey();
  const publicKey = tagged(SUITE_ED25519, await ed.getPublicKeyAsync(secret));
  return { publicKey, secretKey: tagged(SUITE_ED25519, secret) };
}

/** Derive the public key (the name) from a suite-tagged secret key. */
export async function publicKeyOf(secretKey: Uint8Array): Promise<Uint8Array> {
  return tagged(SUITE_ED25519, await ed.getPublicKeyAsync(ed25519SecretOf(secretKey)));
}

/** Sign a byte sequence with a suite-tagged secret key. */
export function sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, ed25519SecretOf(secretKey));
}

/**
 * Verify a signature against a suite-tagged public key. Returns false
 * rather than throwing on mismatch; throws only for a key whose suite
 * this build does not implement (which strict decoding rejects earlier
 * on any wire path).
 */
export async function verifySignature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!isTaggedKey(publicKey)) throw new JinncoreError("unknown key suite");
  try {
    return await ed.verifyAsync(signature, message, publicKey.subarray(1));
  } catch {
    return false;
  }
}
