/**
 * The vault: a capability-gated note store. Run: npx tsx apps/vault/vault.ts
 *
 * Requests are JSON payloads: { op: "read" | "write", key, value? }.
 * Authority is a capability (or delegation chain) in `presents`, issued
 * by the vault's owner. The gate: verified facts from open(), then a
 * dozen lines of the vault's own judgment.
 */

import {
  createGenie,
  equalBytes,
  shortHex,
  verifyDelegationChain,
  type Capability,
  type Envelope,
  type Genie,
  type KeyLike,
} from "../../src/index.js";

const untext = new TextDecoder();

interface Request {
  op: "read" | "write";
  key: string;
  value?: string;
}

class Vault {
  readonly #genie: Genie;
  readonly #owner: Uint8Array;
  readonly #notes = new Map<string, string>();

  constructor(genie: Genie, owner: Uint8Array) {
    this.#genie = genie;
    this.#owner = owner;
  }

  get name(): Uint8Array {
    return this.#genie.name;
  }

  /** The whole service: bytes in, sealed bytes out. Mount on any transport. */
  async handle(bytes: Uint8Array): Promise<Uint8Array> {
    // Mechanical gate: signature, audience, replay, and validity of all
    // presented attestations. Anything invalid throws before we think.
    const envelope = await this.#genie.open(bytes, { requireAudience: true });
    const request = JSON.parse(untext.decode(envelope.payload)) as Request;

    // Judgment gate: the vault's own policy, on top of verified facts.
    await this.#authorize(envelope, `notes/${request.op}`);

    const result =
      request.op === "read"
        ? { ok: true, value: this.#notes.get(request.key) ?? null }
        : (this.#notes.set(request.key, request.value ?? ""), { ok: true });
    return this.#genie.seal({ to: envelope.from, payload: JSON.stringify(result) });
  }

  async #authorize(envelope: Envelope, neededScope: string): Promise<void> {
    // The owner is this vault's root of authority: policy, not wire fact.
    if (equalBytes(envelope.from, this.#owner)) return;

    // Anyone else: a capability chain, rooted at the owner, ending at the
    // presenter, covering the needed scope.
    const chain = (envelope.presents ?? []).filter(
      (a): a is Capability => a.kind === "capability",
    );
    if (chain.length === 0) throw new Error("no capability presented");
    const grant = await verifyDelegationChain(chain);
    if (!equalBytes(grant.issuer, this.#owner)) throw new Error("grant not rooted at my owner");
    if (!equalBytes(grant.subject, envelope.from)) throw new Error("grant is not the presenter's");
    if (!grant.scope.includes(neededScope)) throw new Error(`scope does not cover ${neededScope}`);
  }
}

// --- the demo ---------------------------------------------------------------

const owner = await createGenie();
const alice = await createGenie();
const helper = await createGenie();
const stranger = await createGenie();
const vault = new Vault(await createGenie(), owner.name);

async function attempt(label: string, who: Genie, request: Request, presents?: Capability[]) {
  try {
    const bytes = await who.seal({
      to: vault.name,
      payload: JSON.stringify(request),
      ...(presents && { presents }),
    });
    const reply = await who.open(await vault.handle(bytes), { from: vault.name });
    console.log(`  ${label}: ${untext.decode(reply.payload)}`);
  } catch (error) {
    console.log(`  ${label}: refused — ${(error as Error).message}`);
  }
}

console.log(`vault ${shortHex(vault.name)}, owned by ${shortHex(owner.name)}\n`);

console.log("1. The owner writes a note. Root of authority, no capability needed.");
await attempt("owner writes", owner, { op: "write", key: "motto", value: "grant short, renew often" });

console.log("\n2. The owner grants alice read and write, delegable one hop.");
const aliceCap = await owner.grant(alice, {
  scope: ["notes/read", "notes/write"],
  ttl: 3600,
  hops: 1,
});
await attempt("alice reads", alice, { op: "read", key: "motto" }, [aliceCap]);
await attempt("alice writes", alice, { op: "write", key: "motto", value: "amended by alice" }, [aliceCap]);

console.log("\n3. Alice delegates read-only to her helper. The owner is not consulted.");
const helperCap = await alice.delegate(aliceCap, helper, { scope: ["notes/read"] });
await attempt("helper reads", helper, { op: "read", key: "motto" }, [aliceCap, helperCap]);
await attempt("helper writes", helper, { op: "write", key: "motto", value: "hijacked" }, [aliceCap, helperCap]);

console.log("\n4. The helper tries to delegate onward. Refused at issuance: hops is 0.");
await helper.delegate(helperCap, stranger).catch((e: Error) => console.log(`  ${e.message}`));

console.log("\n5. A stranger, and a thief presenting alice's capability as their own.");
await attempt("stranger reads", stranger, { op: "read", key: "motto" });
await attempt("thief reads", stranger, { op: "read", key: "motto" }, [aliceCap]);

console.log("\n6. An expired capability dies at the mechanical gate, before vault policy runs.");
const stale = await owner.grant(alice, { scope: ["notes/read"], exp: Math.floor(Date.now() / 1000) - 10 });
await attempt("alice, stale grant", alice, { op: "read", key: "motto" }, [stale]);

console.log("\nNo accounts, no sessions, no revocation list: grants, expiry, and one gate.");
