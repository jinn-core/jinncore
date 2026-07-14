import { beforeAll, describe, expect, it } from "vitest";
import { createGenie, createJinn, type Genie, type Jinn } from "../src/index.js";
import { EnvelopeError } from "../src/envelope.js";
import { AttestationError, type Membership } from "../src/attestation.js";
import { JinncoreError } from "../src/errors.js";

let alice: Genie;
let bob: Genie;
let carol: Genie;
let guild: Jinn;

const untext = new TextDecoder();

beforeAll(async () => {
  alice = await createGenie();
  bob = await createGenie();
  carol = await createGenie();
  guild = await createJinn();
});

describe("the quickstart", () => {
  it("two genies exchange a verified message in two calls", async () => {
    const letter = await alice.seal({ to: bob.name, payload: "hello" });
    const envelope = await bob.open(letter);
    expect(envelope.from).toEqual(alice.name);
    expect(untext.decode(envelope.payload)).toBe("hello");
  });

  it("string payloads are UTF-8; byte payloads pass through", async () => {
    const bytes = new Uint8Array([0, 255, 7]);
    const envelope = await bob.open(await alice.seal({ to: bob, payload: bytes }));
    expect(envelope.payload).toEqual(bytes);
  });

  it("a Genie works anywhere a key is expected", async () => {
    const envelope = await bob.open(await alice.seal({ to: bob, payload: "hi" }));
    expect(envelope.aud).toEqual([bob.name]);
  });
});

describe("multi-audience", () => {
  it("an envelope to [bob, carol] opens for both, and for no one else", async () => {
    const letter = await alice.seal({ to: [bob, carol], payload: "team update" });
    await bob.open(letter);
    await carol.open(letter);
    const outsider = await createGenie();
    await expect(outsider.open(letter)).rejects.toThrow("different audience");
  });

  it("audience order does not change the bytes", async () => {
    const nonce = new Uint8Array(16).fill(3);
    const a = await alice.seal({ to: [bob, carol], payload: "x", timestamp: 1, nonce });
    const b = await alice.seal({ to: [carol, bob], payload: "x", timestamp: 1, nonce });
    expect(a).toEqual(b);
  });
});

describe("open() as the mechanical gate", () => {
  it("each genie carries its own replay window", async () => {
    const letter = await alice.seal({ to: bob, payload: "once" });
    await bob.open(letter);
    await expect(bob.open(letter)).rejects.toThrow("already seen");
  });

  it("verifies presented standing by default", async () => {
    const offer = await guild.admit(alice, { role: "scribe", epoch: 1 });
    const membership = await alice.accept(offer);
    // A forged pair: bob's countersignature moved onto alice's statement.
    const bobPair = await bob.accept(await guild.admit(bob, { role: "scribe", epoch: 1 }));
    const franken: Membership = { ...membership, memberSig: bobPair.memberSig };

    const honest = await alice.seal({ to: bob, payload: "hi", presents: [membership] });
    await bob.open(honest); // fine

    // seal() itself shape-checks but cannot catch cross-signature forgery;
    // open() must.
    const forged = await alice.seal({ to: bob, payload: "hi", presents: [franken] });
    await expect(bob.open(forged)).rejects.toThrow("countersignature");
    await expect(bob.open(forged, { verifyPresents: false })).rejects.toThrow("already seen"); // replay, not forgery: opt-out skipped the check
  });

  it("rejects expired standing on this genie's clock", async () => {
    const membership = await alice.accept(await guild.admit(alice, { role: "scribe", ttl: 10 }));
    const letter = await alice.seal({ to: bob, payload: "hi", presents: [membership] });
    const future = Math.floor(Date.now() / 1000) + 60;
    await expect(bob.open(letter, { now: future })).rejects.toThrow(/expired|tolerance/);
  });

  it("can demand an audience", async () => {
    const publicLetter = await alice.seal({ payload: "to whom it may concern" });
    await expect(bob.open(publicLetter, { requireAudience: true })).rejects.toThrow(
      "audience required",
    );
  });
});

describe("granting and delegating", () => {
  it("grants default to one hour and zero hops", async () => {
    const before = Math.floor(Date.now() / 1000);
    const cap = await alice.grant(bob, { scope: ["orders/read"] });
    expect(cap.hops).toBe(0);
    expect(cap.exp).toBeGreaterThanOrEqual(before + 3600);
    expect(cap.exp).toBeLessThanOrEqual(before + 3610);
  });

  it("delegation defaults are the parent's bounds, one hop shorter", async () => {
    const parent = await alice.grant(bob, { scope: ["a", "b"], hops: 2, ttl: 100 });
    const child = await bob.delegate(parent, carol);
    expect(child.scope).toEqual(parent.scope);
    expect(child.exp).toBe(parent.exp);
    expect(child.hops).toBe(1);
  });

  it("refuses widening at issuance, before any verifier", async () => {
    const parent = await alice.grant(bob, { scope: ["a"], hops: 1, ttl: 100 });
    await expect(bob.delegate(parent, carol, { scope: ["a", "z"] })).rejects.toThrow("widen scope");
    await expect(bob.delegate(parent, carol, { exp: parent.exp + 1 })).rejects.toThrow("extend expiry");
    await expect(bob.delegate(parent, carol, { hops: 1 })).rejects.toThrow("shrink hops");
  });

  it("only the subject can delegate, and hops 0 cannot", async () => {
    const parent = await alice.grant(bob, { scope: ["a"], hops: 1 });
    await expect(carol.delegate(parent, bob)).rejects.toThrow("only the capability's subject");
    const dead = await alice.grant(bob, { scope: ["a"], hops: 0 });
    await expect(bob.delegate(dead, carol)).rejects.toThrow("not delegable");
  });
});

describe("societies", () => {
  it("admit then accept yields a verifying pair; accepting someone else's offer fails", async () => {
    const offer = await guild.admit(alice, { role: "scribe", epoch: 2 });
    const membership = await alice.accept(offer);
    expect(membership.role).toBe("scribe");
    await expect(bob.accept(offer)).rejects.toThrow("not addressed to this key");
  });

  it("a jinn can also speak and listen like any genie", async () => {
    const letter = await guild.seal({ to: alice, payload: "welcome" });
    const envelope = await alice.open(letter);
    expect(envelope.from).toEqual(guild.name);
  });
});

describe("persistence", () => {
  it("export and restore keep the name; the soul is the secret key", async () => {
    const soul = alice.export();
    const restored = await createGenie({ secretKey: soul });
    expect(restored.name).toEqual(alice.name);
    // The restored genie can open letters addressed to the original name.
    const letter = await bob.seal({ to: alice.name, payload: "still you?" });
    const envelope = await restored.open(letter);
    expect(untext.decode(envelope.payload)).toBe("still you?");
  });

  it("export returns a copy, not the internal buffer", () => {
    const soul = alice.export();
    soul.fill(0);
    expect(alice.export()).not.toEqual(soul);
  });
});

describe("errors", () => {
  it("everything thrown is a JinncoreError", async () => {
    const letter = await alice.seal({ to: bob, payload: "x" });
    const errors: unknown[] = [];
    await bob.open(letter);
    await bob.open(letter).catch((e) => errors.push(e));
    await bob.open(new Uint8Array([1, 2, 3])).catch((e) => errors.push(e));
    const parent = await alice.grant(bob, { scope: ["a"], hops: 0 });
    await bob.delegate(parent, carol).catch((e) => errors.push(e));
    expect(errors).toHaveLength(3);
    for (const e of errors) expect(e).toBeInstanceOf(JinncoreError);
    expect(errors[0]).toBeInstanceOf(EnvelopeError);
  });
});
