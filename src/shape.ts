/** Shape checks shared by every wire-object parser. */

import type { WireValue } from "./cbor.js";

export function isPlainMap(value: WireValue | undefined): value is { [key: string]: WireValue } {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
  );
}

export function isBytes(value: WireValue | undefined, length?: number): value is Uint8Array {
  return value instanceof Uint8Array && (length === undefined || value.length === length);
}

export function isUint(value: WireValue | undefined): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** Enforce a closed shape: all required keys present, nothing unknown. */
export function requireKeys(
  map: { [key: string]: WireValue },
  required: string[],
  optional: string[],
  error: new (message: string) => Error,
): void {
  const keys = Object.keys(map);
  for (const key of required) {
    if (!keys.includes(key)) throw new error(`missing field: ${key}`);
  }
  for (const key of keys) {
    if (!required.includes(key) && !optional.includes(key)) {
      throw new error(`unknown field: ${key}`);
    }
  }
}
