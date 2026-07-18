/**
 * Sigil (SPEC.md §7, provisional): keyless, inert, shareable definition
 * text, fixing a behavior and its membrane policy and nothing else. Dead
 * things are named by content: a sigil's true name is the SHA-256 digest
 * of its canonical bytes. Everything a summoner chooses at kindling (the
 * brain, the budget, the payer, an alias) stays outside the sigil and
 * outside its name.
 */

import { decodeWire, encodeWire, type WireValue } from "./cbor.js";
import { compareBytes } from "./bytes.js";
import { sha256 } from "./digest.js";
import { JinncoreError } from "./errors.js";
import { isKey, isPlainMap, requireKeys } from "./shape.js";

export const SIGIL_VERSION = 1;

export class SigilError extends JinncoreError {}

/** Who may wake a genie kindled from this sigil. */
export type SigilMembrane =
  | { gate: "open" }
  | { gate: "utterer" }
  | { gate: "allow"; keys: Uint8Array[] };

export interface Sigil {
  v: number;
  behavior: string;
  membrane: SigilMembrane;
}

export interface EncodeSigilOptions {
  /** The behavior; opaque to the grammar, the brain's instructions. */
  behavior: string;
  /** The membrane policy. Omitted means open. */
  membrane?: SigilMembrane;
}

function canonicalMembrane(membrane: SigilMembrane): SigilMembrane {
  switch (membrane.gate) {
    case "open":
    case "utterer":
      return { gate: membrane.gate };
    case "allow": {
      const keys = [...membrane.keys];
      if (keys.length === 0) {
        throw new SigilError("allow membrane needs at least one key");
      }
      for (const key of keys) {
        if (!isKey(key)) throw new SigilError("membrane keys must be suite-tagged keys");
      }
      keys.sort(compareBytes);
      for (let i = 1; i < keys.length; i++) {
        if (compareBytes(keys[i - 1]!, keys[i]!) === 0) {
          throw new SigilError("membrane keys must be unique");
        }
      }
      return { gate: "allow", keys };
    }
    default:
      throw new SigilError(`unknown membrane gate: ${String((membrane as SigilMembrane).gate)}`);
  }
}

/**
 * Encode a sigil to its one canonical byte form, the form its name is
 * computed over.
 *
 * @example
 * const bytes = encodeSigil({ behavior: "You are a scribe.", membrane: { gate: "utterer" } });
 * const name = await hashSigil(bytes);
 */
export function encodeSigil(options: EncodeSigilOptions): Uint8Array {
  if (typeof options.behavior !== "string" || options.behavior.length === 0) {
    throw new SigilError("behavior must be non-empty text");
  }
  const membrane = canonicalMembrane(options.membrane ?? { gate: "open" });
  return encodeWire({
    v: SIGIL_VERSION,
    behavior: options.behavior,
    membrane: membrane as unknown as WireValue,
  });
}

/** Strict-decode and shape-check sigil bytes (SPEC.md §7). */
export function parseSigil(bytes: Uint8Array): Sigil {
  let value: WireValue;
  try {
    value = decodeWire(bytes);
  } catch (error) {
    throw new SigilError(`not canonical wire bytes: ${(error as Error).message}`);
  }
  if (!isPlainMap(value)) throw new SigilError("sigil must be a map");
  requireKeys(value, ["v", "behavior", "membrane"], [], SigilError);
  if (value.v !== SIGIL_VERSION) {
    throw new SigilError(`unsupported sigil version: ${String(value.v)}`);
  }
  if (typeof value.behavior !== "string" || value.behavior.length === 0) {
    throw new SigilError("behavior must be non-empty text");
  }

  const membrane = value.membrane;
  if (!isPlainMap(membrane)) throw new SigilError("membrane must be a map");
  switch (membrane.gate) {
    case "open":
    case "utterer": {
      requireKeys(membrane, ["gate"], [], SigilError);
      return { v: value.v, behavior: value.behavior, membrane: { gate: membrane.gate } };
    }
    case "allow": {
      requireKeys(membrane, ["gate", "keys"], [], SigilError);
      const keys = membrane.keys;
      if (!Array.isArray(keys) || keys.length === 0) {
        throw new SigilError("allow membrane needs a non-empty key array");
      }
      const list: Uint8Array[] = [];
      for (const key of keys) {
        if (!isKey(key)) throw new SigilError("membrane keys must be suite-tagged keys");
        if (list.length > 0 && compareBytes(list[list.length - 1]!, key) >= 0) {
          throw new SigilError("membrane keys must be strictly ascending and unique");
        }
        list.push(key);
      }
      return { v: value.v, behavior: value.behavior, membrane: { gate: "allow", keys: list } };
    }
    default:
      throw new SigilError(`unknown membrane gate: ${String(membrane.gate)}`);
  }
}

/**
 * A sigil's true name: the SHA-256 digest of its canonical bytes. The
 * bytes are parsed first, so a malformed sigil has no name.
 */
export async function hashSigil(bytes: Uint8Array): Promise<Uint8Array> {
  parseSigil(bytes);
  return sha256(bytes);
}
