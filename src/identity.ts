/**
 * Identity (SPEC.md §4): a genie's name is an Ed25519 public key it mints
 * for itself at kindling. This module wraps the primitive; where the
 * secret half sleeps is key custody, below the waist, the caller's
 * business.
 */

import * as ed from "@noble/ed25519";

export const PUBLIC_KEY_LENGTH = 32;
export const SECRET_KEY_LENGTH = 32;
export const SIGNATURE_LENGTH = 64;

/** A keypair: the public half is the name, the secret half never travels. */
export interface Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Mint a fresh identity. */
export async function mintKeypair(): Promise<Keypair> {
  const secretKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(secretKey);
  return { publicKey, secretKey };
}

/** Derive the public key (the name) from a secret key. */
export function publicKeyOf(secretKey: Uint8Array): Promise<Uint8Array> {
  return ed.getPublicKeyAsync(secretKey);
}

/** Sign a byte sequence. */
export function sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, secretKey);
}

/** Verify a signature. Returns false rather than throwing on mismatch. */
export async function verifySignature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}
