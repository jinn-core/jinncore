import { describe, expect, it } from "vitest";
import {
  encodeSigil,
  parseSigil,
  hashSigil,
  encodeWire,
  generateKeypair,
  toHex,
} from "../src/wire.js";

describe("sigil encoding and naming", () => {
  it("round-trips and defaults the membrane to open", async () => {
    const bytes = encodeSigil({ behavior: "You are a scribe." });
    const sigil = parseSigil(bytes);
    expect(sigil).toEqual({ v: 1, behavior: "You are a scribe.", membrane: { gate: "open" } });
    expect((await hashSigil(bytes)).length).toBe(32);
  });

  it("same design, same name; different design, different name", async () => {
    const a = encodeSigil({ behavior: "Translate.", membrane: { gate: "utterer" } });
    const b = encodeSigil({ behavior: "Translate.", membrane: { gate: "utterer" } });
    const c = encodeSigil({ behavior: "Translate!", membrane: { gate: "utterer" } });
    expect(toHex(await hashSigil(a))).toBe(toHex(await hashSigil(b)));
    expect(toHex(await hashSigil(a))).not.toBe(toHex(await hashSigil(c)));
  });

  it("canonicalizes allow keys by sorting; order at encode time does not change the name", async () => {
    const one = await generateKeypair();
    const two = await generateKeypair();
    const ab = encodeSigil({
      behavior: "Talk to friends.",
      membrane: { gate: "allow", keys: [one.publicKey, two.publicKey] },
    });
    const ba = encodeSigil({
      behavior: "Talk to friends.",
      membrane: { gate: "allow", keys: [two.publicKey, one.publicKey] },
    });
    expect(toHex(await hashSigil(ab))).toBe(toHex(await hashSigil(ba)));
    const parsed = parseSigil(ab);
    expect(parsed.membrane.gate).toBe("allow");
  });

  it("rejects malformed sigils", async () => {
    const key = (await generateKeypair()).publicKey;
    expect(() => encodeSigil({ behavior: "" })).toThrow("behavior must be non-empty");
    expect(() =>
      encodeSigil({ behavior: "x", membrane: { gate: "allow", keys: [] } }),
    ).toThrow("at least one key");
    expect(() =>
      encodeSigil({ behavior: "x", membrane: { gate: "allow", keys: [key, key] } }),
    ).toThrow("unique");
    expect(() =>
      encodeSigil({ behavior: "x", membrane: { gate: "allow", keys: [new Uint8Array(32)] } }),
    ).toThrow("suite-tagged");
    // hand-built wire values that a strict parser must refuse
    const reject = (value: unknown, message: string) =>
      expect(() => parseSigil(encodeWire(value as never))).toThrow(message);
    reject({ v: 2, behavior: "x", membrane: { gate: "open" } }, "unsupported sigil version");
    reject({ v: 1, behavior: "x", membrane: { gate: "royal" } }, "unknown membrane gate");
    reject({ v: 1, behavior: "x", membrane: { gate: "open" }, extra: 1 }, "unknown field");
    reject({ v: 1, behavior: "x", membrane: { gate: "open", keys: [] } }, "unknown field");
    reject({ v: 1, membrane: { gate: "open" } }, "missing field");
    reject(
      { v: 1, behavior: "x", membrane: { gate: "allow", keys: [key, key] } },
      "strictly ascending",
    );
    // a malformed sigil has no name
    await expect(hashSigil(encodeWire({ v: 1 }))).rejects.toThrow("missing field");
  });
});
