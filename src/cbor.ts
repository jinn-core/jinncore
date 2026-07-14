/**
 * Deterministic CBOR (RFC 8949 §4.2.1) codec, restricted to the Jinn wire
 * subset (SPEC.md §3): 64-bit integers, byte strings, UTF-8 text strings,
 * arrays, maps with text keys, false, true, null.
 *
 * decodeWire() is strict: it accepts exactly the bytes encodeWire() can
 * produce, so every wire value has one encoding and a signature over
 * canonical bytes covers one value.
 */

import { compareBytes } from "./bytes.js";
import { JinncoreError } from "./errors.js";

export type WireValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | WireValue[]
  | { [key: string]: WireValue };

const MAX_U64 = (1n << 64n) - 1n;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export class WireEncodeError extends JinncoreError {}
export class WireDecodeError extends JinncoreError {}

// --- encoding ---------------------------------------------------------

function pushHead(out: number[], major: number, arg: bigint): void {
  const mt = major << 5;
  if (arg < 24n) {
    out.push(mt | Number(arg));
  } else if (arg <= 0xffn) {
    out.push(mt | 24, Number(arg));
  } else if (arg <= 0xffffn) {
    out.push(mt | 25, Number(arg >> 8n), Number(arg & 0xffn));
  } else if (arg <= 0xffffffffn) {
    out.push(mt | 26);
    for (let shift = 24n; shift >= 0n; shift -= 8n) {
      out.push(Number((arg >> shift) & 0xffn));
    }
  } else {
    out.push(mt | 27);
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      out.push(Number((arg >> shift) & 0xffn));
    }
  }
}

function pushInteger(out: number[], value: bigint): void {
  if (value >= 0n) {
    if (value > MAX_U64) throw new WireEncodeError(`integer too large: ${value}`);
    pushHead(out, 0, value);
  } else {
    const arg = -1n - value;
    if (arg > MAX_U64) throw new WireEncodeError(`integer too small: ${value}`);
    pushHead(out, 1, arg);
  }
}

function pushValue(out: number[], value: WireValue): void {
  if (value === null) {
    out.push(0xf6);
  } else if (value === false) {
    out.push(0xf4);
  } else if (value === true) {
    out.push(0xf5);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new WireEncodeError(`not an integer in the wire subset: ${value}`);
    }
    pushInteger(out, BigInt(value));
  } else if (typeof value === "bigint") {
    pushInteger(out, value);
  } else if (typeof value === "string") {
    const bytes = utf8Encoder.encode(value);
    pushHead(out, 3, BigInt(bytes.length));
    for (const b of bytes) out.push(b);
  } else if (value instanceof Uint8Array) {
    pushHead(out, 2, BigInt(value.length));
    for (const b of value) out.push(b);
  } else if (Array.isArray(value)) {
    pushHead(out, 4, BigInt(value.length));
    for (const item of value) pushValue(out, item);
  } else if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value).map(([key, item]) => {
      const keyBytes: number[] = [];
      pushValue(keyBytes, key);
      return { keyBytes: Uint8Array.from(keyBytes), item };
    });
    entries.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
    pushHead(out, 5, BigInt(entries.length));
    for (const { keyBytes, item } of entries) {
      for (const b of keyBytes) out.push(b);
      pushValue(out, item);
    }
  } else {
    throw new WireEncodeError(`value outside the wire subset: ${String(value)}`);
  }
}

/**
 * Encode a wire value as deterministic CBOR: the one byte representation
 * every signature in the protocol is computed over.
 *
 * @example
 * const bytes = encodeWire({ hello: "world", n: 5 });
 */
export function encodeWire(value: WireValue): Uint8Array {
  const out: number[] = [];
  pushValue(out, value);
  return Uint8Array.from(out);
}

// --- strict decoding --------------------------------------------------

class Reader {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}

  byte(): number {
    if (this.pos >= this.buf.length) throw new WireDecodeError("truncated input");
    return this.buf[this.pos++]!;
  }

  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new WireDecodeError("truncated input");
    const slice = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }
}

interface Head {
  major: number;
  arg: bigint;
}

function readHead(r: Reader): Head {
  const initial = r.byte();
  const major = initial >> 5;
  const info = initial & 0x1f;
  let arg: bigint;
  if (info < 24) {
    arg = BigInt(info);
  } else if (info === 24) {
    arg = BigInt(r.byte());
    if (arg < 24n) throw new WireDecodeError("non-shortest argument encoding");
  } else if (info === 25 || info === 26 || info === 27) {
    const width = info === 25 ? 2 : info === 26 ? 4 : 8;
    arg = 0n;
    for (const b of r.bytes(width)) arg = (arg << 8n) | BigInt(b);
    const floor = info === 25 ? 0xffn : info === 26 ? 0xffffn : 0xffffffffn;
    if (arg <= floor) throw new WireDecodeError("non-shortest argument encoding");
  } else if (info === 31) {
    throw new WireDecodeError("indefinite lengths are outside the wire subset");
  } else {
    throw new WireDecodeError(`reserved additional information: ${info}`);
  }
  return { major, arg };
}

function argToLength(arg: bigint): number {
  if (arg > BigInt(Number.MAX_SAFE_INTEGER)) throw new WireDecodeError("length too large");
  return Number(arg);
}

function asInteger(arg: bigint, negative: boolean): number | bigint {
  const value = negative ? -1n - arg : arg;
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

function readValue(r: Reader): WireValue {
  const { major, arg } = readHead(r);
  switch (major) {
    case 0:
      return asInteger(arg, false);
    case 1:
      return asInteger(arg, true);
    case 2:
      return Uint8Array.from(r.bytes(argToLength(arg)));
    case 3: {
      const bytes = r.bytes(argToLength(arg));
      try {
        return utf8Decoder.decode(bytes);
      } catch {
        throw new WireDecodeError("invalid UTF-8 in text string");
      }
    }
    case 4: {
      const length = argToLength(arg);
      const items: WireValue[] = [];
      for (let i = 0; i < length; i++) items.push(readValue(r));
      return items;
    }
    case 5: {
      const length = argToLength(arg);
      const map: { [key: string]: WireValue } = {};
      let prevKeyBytes: Uint8Array | null = null;
      for (let i = 0; i < length; i++) {
        const keyStart = r.pos;
        const keyHead = readHead(r);
        if (keyHead.major !== 3) {
          throw new WireDecodeError("map keys must be text strings");
        }
        const keyContent = r.bytes(argToLength(keyHead.arg));
        let key: string;
        try {
          key = utf8Decoder.decode(keyContent);
        } catch {
          throw new WireDecodeError("invalid UTF-8 in map key");
        }
        const keyBytes = r.buf.subarray(keyStart, r.pos);
        if (prevKeyBytes !== null && compareBytes(prevKeyBytes, keyBytes) >= 0) {
          throw new WireDecodeError("map keys not in canonical order");
        }
        prevKeyBytes = keyBytes;
        // defineProperty, not assignment: a hostile "__proto__" key must
        // become an ordinary own entry, never touch the prototype chain.
        Object.defineProperty(map, key, {
          value: readValue(r),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return map;
    }
    case 6:
      throw new WireDecodeError("tags are outside the wire subset");
    case 7:
      switch (arg) {
        case 20n:
          return false;
        case 21n:
          return true;
        case 22n:
          return null;
        default:
          throw new WireDecodeError(`simple/float value outside the wire subset: ${arg}`);
      }
    default:
      throw new WireDecodeError(`unreachable major type: ${major}`);
  }
}

/**
 * Decode deterministic CBOR, rejecting any input that is not the canonical
 * encoding of a value in the wire subset.
 *
 * @example
 * const value = decodeWire(bytes); // throws WireDecodeError on anything non-canonical
 */
export function decodeWire(bytes: Uint8Array): WireValue {
  const r = new Reader(bytes);
  const value = readValue(r);
  if (r.pos !== bytes.length) throw new WireDecodeError("trailing bytes after value");
  return value;
}
