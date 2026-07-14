/** Byte-level helpers shared across the grammar. */

import { JinncoreError } from "./errors.js";

/** Bytewise lexicographic comparison (RFC 8949 §4.2.1 map-key order). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * @example
 * toHex(keypair.publicKey); // "a1b2c3…"
 */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * A key abbreviated for logs and eyes: "a1b2c3d4…". Display only; never
 * compare short forms.
 *
 * @example
 * console.log(`from ${shortHex(envelope.from)}`);
 */
export function shortHex(bytes: Uint8Array, chars = 8): string {
  return toHex(bytes).slice(0, chars) + "…";
}

/**
 * @example
 * const key = fromHex("a1b2c3…"); // Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new JinncoreError("fromHex expects an even-length hexadecimal string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
