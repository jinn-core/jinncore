import { describe, expect, it } from "vitest";
import { decodeWire, encodeWire, WireDecodeError, WireEncodeError, type WireValue } from "../src/cbor.js";

function fromHex(hex: string): Uint8Array {
  const clean = hex.replaceAll(" ", "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("encode", () => {
  // RFC 8949 Appendix A examples, restricted to the wire subset.
  const rfcExamples: Array<[WireValue, string]> = [
    [0, "00"],
    [1, "01"],
    [10, "0a"],
    [23, "17"],
    [24, "1818"],
    [25, "1819"],
    [100, "1864"],
    [1000, "1903e8"],
    [1000000, "1a000f4240"],
    [1000000000000, "1b000000e8d4a51000"],
    [(1n << 64n) - 1n, "1bffffffffffffffff"],
    [-1, "20"],
    [-10, "29"],
    [-100, "3863"],
    [-1000, "3903e7"],
    [-(1n << 64n), "3bffffffffffffffff"],
    [false, "f4"],
    [true, "f5"],
    [null, "f6"],
    ["", "60"],
    ["a", "6161"],
    ["IETF", "6449455446"],
    ['"\\', "62225c"],
    ["ü", "62c3bc"],
    ["水", "63e6b0b4"],
    [new Uint8Array(), "40"],
    [new Uint8Array([1, 2, 3, 4]), "4401020304"],
    [[], "80"],
    [[1, 2, 3], "83010203"],
    [[1, [2, 3], [4, 5]], "8301820203820405"],
    [{}, "a0"],
    [{ a: 1, b: [2, 3] }, "a26161016162820203"],
    [["a", { b: "c" }], "826161a161626163"],
  ];

  for (const [value, hex] of rfcExamples) {
    it(`encodes ${JSON.stringify(value, (_, v) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? toHex(v) : v))} as ${hex}`, () => {
      expect(toHex(encodeWire(value))).toBe(hex);
    });
  }

  it("sorts map keys bytewise regardless of insertion order", () => {
    expect(toHex(encodeWire({ b: 2, a: 1 }))).toBe("a2616101616202");
    // Shorter key encodes lower than a longer key sharing its prefix.
    expect(toHex(encodeWire({ aa: 2, a: 1 }))).toBe("a261610162616102");
  });

  it("rejects values outside the subset", () => {
    expect(() => encodeWire(1.5)).toThrow(WireEncodeError);
    expect(() => encodeWire(NaN)).toThrow(WireEncodeError);
    expect(() => encodeWire(1n << 64n)).toThrow(WireEncodeError);
    expect(() => encodeWire(-(1n << 64n) - 1n)).toThrow(WireEncodeError);
    expect(() => encodeWire(undefined as unknown as WireValue)).toThrow(WireEncodeError);
    expect(() => encodeWire(new Date() as unknown as WireValue)).toThrow(WireEncodeError);
    expect(() => encodeWire(new Map() as unknown as WireValue)).toThrow(WireEncodeError);
  });
});

describe("strict decode", () => {
  it("round-trips every encodable value", () => {
    const values: WireValue[] = [
      0,
      -1,
      23,
      24,
      1000000,
      (1n << 64n) - 1n,
      -(1n << 64n),
      "",
      "IETF",
      "水",
      new Uint8Array([1, 2, 3, 4]),
      [1, [2, 3], "x", null],
      { a: 1, b: [2, 3], c: { d: new Uint8Array([9]) } },
      true,
      false,
      null,
    ];
    for (const value of values) {
      const bytes = encodeWire(value);
      expect(encodeWire(decodeWire(bytes))).toEqual(bytes);
    }
  });

  const rejections: Array<[string, string]> = [
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

  for (const [hex, label] of rejections) {
    it(`rejects ${label} (${hex || "<empty>"})`, () => {
      expect(() => decodeWire(fromHex(hex))).toThrow(WireDecodeError);
    });
  }

  it("accepts exactly the canonical encoding of a map", () => {
    const canonical = "a26161016162820203";
    expect(toHex(encodeWire(decodeWire(fromHex(canonical))))).toBe(canonical);
  });
});

describe("prototype safety", () => {
  it('treats a hostile "__proto__" key as an ordinary entry', () => {
    // {"__proto__": {"polluted": 1}}
    const bytes = encodeWire({ ["__proto__"]: { polluted: 1 } } as unknown as WireValue);
    const value = decodeWire(bytes) as { [key: string]: WireValue };
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(value, "__proto__")?.value).toEqual({ polluted: 1 });
  });
});
