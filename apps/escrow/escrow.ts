/**
 * The escrow: atomic swap of two capabilities between mutually
 * distrusting parties. Run: npx tsx apps/escrow/escrow.ts
 *
 * A deposit is an envelope to the escrow whose payload names the deal and
 * what the depositor wants in return, and whose `presents` carries the
 * capability they give (issued to the counterparty, not to the escrow:
 * the escrow holds it but could never use it). When both deposits match,
 * the escrow seals ONE release envelope addressed to both parties.
 */

import {
  createGenie,
  equalBytes,
  shortHex,
  toHex,
  type Capability,
  type Genie,
} from "../../src/index.js";

interface DepositTerms {
  deal: string;
  want: { from: string; scope: string[] }; // what I expect the other side to give
}

interface Deposit {
  from: Uint8Array;
  terms: DepositTerms;
  gives: Capability;
}

class Escrow {
  readonly #genie: Genie;
  readonly #deals = new Map<string, Deposit[]>();

  constructor(genie: Genie) {
    this.#genie = genie;
  }

  get name(): Uint8Array {
    return this.#genie.name;
  }

  /** Returns sealed envelopes to deliver: an ack, plus the release when a deal completes. */
  async handle(bytes: Uint8Array): Promise<Uint8Array[]> {
    const envelope = await this.#genie.open(bytes, { requireAudience: true });
    const terms = envelope.json<DepositTerms>();
    const gives = (envelope.presents ?? []).find(
      (a): a is Capability => a.kind === "capability",
    );

    // On-protocol checks only: you deposit your own grant, made out to
    // someone who is not you and not me. Worth is not checkable.
    if (!gives) throw new Error("deposit carries no capability");
    if (!equalBytes(gives.issuer, envelope.from)) throw new Error("deposit a grant of your own");
    if (equalBytes(gives.subject, envelope.from) || equalBytes(gives.subject, this.name)) {
      throw new Error("the grant must be made out to your counterparty");
    }

    const deposits = this.#deals.get(terms.deal) ?? [];
    deposits.push({ from: envelope.from, terms, gives });
    this.#deals.set(terms.deal, deposits);

    const ack = await this.#genie.seal({
      to: envelope.from,
      payload: JSON.stringify({ deal: terms.deal, held: true }),
    });
    const release = deposits.length === 2 ? await this.#tryRelease(deposits) : null;
    return release ? [ack, release] : [ack];
  }

  /** Both sides in: release only if each deposit gives what the other wants. */
  async #tryRelease([a, b]: Deposit[]): Promise<Uint8Array | null> {
    const satisfies = (give: Deposit, want: Deposit): boolean =>
      toHex(give.from) === want.terms.want.from &&
      equalBytes(give.gives.subject, want.from) &&
      want.terms.want.scope.every((s) => give.gives.scope.includes(s));
    if (!satisfies(a!, b!) || !satisfies(b!, a!)) {
      console.log("  escrow: terms do not match; holding both deposits until they expire");
      return null;
    }
    return this.#genie.seal({
      to: [a!.from, b!.from],
      presents: [a!.gives, b!.gives],
      payload: JSON.stringify({ deal: a!.terms.deal, released: true }),
    });
  }
}

// --- the demo ---------------------------------------------------------------

const buyer = await createGenie();
const seller = await createGenie();
const escrow = new Escrow(await createGenie());

console.log(`escrow ${shortHex(escrow.name)}; buyer ${shortHex(buyer.name)}; seller ${shortHex(seller.name)}\n`);

async function deposit(who: Genie, terms: DepositTerms, gives: Capability): Promise<Uint8Array[]> {
  const bytes = await who.seal({
    to: escrow.name,
    payload: JSON.stringify(terms),
    presents: [gives],
  });
  const out = await escrow.handle(bytes);
  const ack = await who.open(out[0]!, { from: escrow.name });
  console.log(`  ${shortHex(who.name)} deposits: ${ack.text()}`);
  return out.slice(1);
}

console.log("1. Deal-42: archive access for treasury access. The seller deposits first.");
const sellerGives = await seller.grant(buyer, { scope: ["archive/read"], ttl: 600 });
await deposit(
  seller,
  { deal: "deal-42", want: { from: buyer.hex, scope: ["treasury/draw"] } },
  sellerGives,
);

console.log("\n2. The buyer deposits the matching side. The escrow releases atomically.");
const buyerGives = await buyer.grant(seller, { scope: ["treasury/draw"], ttl: 600 });
const [release] = await deposit(
  buyer,
  { deal: "deal-42", want: { from: seller.hex, scope: ["archive/read"] } },
  buyerGives,
);

console.log("\n3. One release envelope, addressed to both. Each opens the same bytes.");
for (const party of [buyer, seller]) {
  const opened = await party.open(release!, { from: escrow.name });
  const mine = opened.presents!.find((a) => equalBytes(a.subject, party.name))!;
  console.log(`  ${shortHex(party.name)} receives a grant of [${(mine as Capability).scope}] from ${shortHex(mine.issuer)}`);
}

console.log("\n4. Both parties testify: this is how an escrow accumulates the standing it sells.");
const praise = await buyer.testify(escrow.name, { body: "deal-42 released as agreed", ttl: 86400 });
console.log(`  buyer signs testimony about ${shortHex(praise.subject)}: "deal-42 released as agreed"`);

console.log("\n5. Deal-43: the buyer offers the wrong scope. No release; expiry cleans up.");
await deposit(
  seller,
  { deal: "deal-43", want: { from: buyer.hex, scope: ["treasury/draw"] } },
  await seller.grant(buyer, { scope: ["archive/read"], ttl: 600 }),
);
await deposit(
  buyer,
  { deal: "deal-43", want: { from: seller.hex, scope: ["archive/read"] } },
  await buyer.grant(seller, { scope: ["treasury/peek"], ttl: 600 }),
);

console.log("\nNobody went first, nobody could be left holding nothing, and the failure path was silence plus expiry.");
