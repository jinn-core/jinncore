/**
 * The high-level layer: living protocol actors.
 *
 * A Genie object is the protocol half of a genie: its name, its voice,
 * and its gate. You supply the brain (your code) and the lamp (the
 * process you run it in). A Jinn is a society: a Genie whose key also
 * admits members.
 *
 * This layer ends at the waist: no transport, no storage, no message
 * loop, no policy. Its state is exactly a secret key and a replay window.
 *
 * @example
 * const alice = await createGenie();
 * const bob = await createGenie();
 * const letter = await alice.seal({ to: bob.name, payload: "hello" });
 * const envelope = await bob.open(letter); // verified, or it throws
 */

import { equalBytes, fromHex, toHex } from "./bytes.js";
import { JinncoreError } from "./errors.js";
import { generateKeypair, publicKeyOf } from "./identity.js";
import {
  EnvelopeError,
  FreshnessWindow,
  type FreshnessSnapshot,
  sealEnvelope,
  verifyEnvelope,
  type Envelope,
} from "./envelope.js";
import {
  acceptMembership,
  grantMembership,
  issueCapability,
  issueTestimony,
  verifyAttestation,
  type Attestation,
  type Capability,
  type Membership,
  type MembershipOffer,
  type Testimony,
} from "./attestation.js";

/**
 * Anywhere a key is expected: raw bytes, a hex string, or a Genie (or
 * anything else with a name) all work.
 */
export type KeyLike = Uint8Array | string | { name: Uint8Array };

const keyOf = (k: KeyLike): Uint8Array =>
  k instanceof Uint8Array ? k : typeof k === "string" ? fromHex(k) : k.name;

const utf8 = new TextEncoder();
const untext = new TextDecoder();
const toBytes = (p: string | Uint8Array): Uint8Array =>
  typeof p === "string" ? utf8.encode(p) : p;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** Grants are short-lived unless you say otherwise: one hour. */
export const DEFAULT_TTL = 3600;

export interface CreateOptions {
  /** Restore an existing identity instead of generating a fresh one. */
  secretKey?: Uint8Array;
  /** Replay-window tolerance in seconds (default 300). */
  tolerance?: number;
  /** Restore a saved replay window (from freshnessSnapshot()). */
  freshness?: FreshnessSnapshot;
}

export interface GenieSealOptions {
  payload: string | Uint8Array;
  /** Recipient(s). Omit for a public envelope. */
  to?: KeyLike | KeyLike[];
  /** Standing to present alongside the message. */
  presents?: Attestation[];
  /** Override the sender's clock (mostly for tests). */
  timestamp?: number;
  /** Override the random nonce (mostly for tests). */
  nonce?: Uint8Array;
}

export interface GenieOpenOptions {
  /** Reject envelopes not sent by this key. */
  from?: KeyLike;
  /** Reject public envelopes outright. */
  requireAudience?: boolean;
  /**
   * Presented attestations are cryptographically verified by default
   * (signatures, pairs, expiry). Set false to skip and judge raw shapes.
   */
  verifyPresents?: boolean;
  /** Override this genie's clock (mostly for tests). */
  now?: number;
}

/** An opened envelope, with payload conveniences attached. */
export type OpenedEnvelope = Envelope & {
  /** The payload as UTF-8 text. */
  text(): string;
  /** The payload parsed as JSON. */
  json<T = unknown>(): T;
};

interface TtlOptions {
  /** Seconds of validity from now (default DEFAULT_TTL). */
  ttl?: number;
  /** Absolute expiry in seconds; overrides ttl. */
  exp?: number;
}

const expiryOf = (options: TtlOptions, now: number): number =>
  options.exp ?? now + (options.ttl ?? DEFAULT_TTL);

export class Genie {
  /** A genie's true name is its key. */
  readonly name: Uint8Array;
  readonly #secretKey: Uint8Array;
  readonly #window: FreshnessWindow;

  protected constructor(
    secretKey: Uint8Array,
    name: Uint8Array,
    tolerance: number,
    freshness?: FreshnessSnapshot,
  ) {
    this.#secretKey = secretKey;
    this.name = name;
    this.#window = new FreshnessWindow(tolerance, freshness);
  }

  static async create(options: CreateOptions = {}): Promise<Genie> {
    const { secretKey, name } = await resolveIdentity(options);
    return new Genie(secretKey, name, options.tolerance ?? 300, options.freshness);
  }

  /** The replay window's seen markers, for persistence across restarts. */
  freshnessSnapshot(): FreshnessSnapshot {
    return this.#window.snapshot();
  }

  /** The name as lowercase hex, for logs and comparisons by eye. */
  get hex(): string {
    return toHex(this.name);
  }

  /**
   * Seal an envelope: write, sign, close. Anything altered afterwards
   * breaks the seal. Returns wire bytes for any channel you like.
   */
  seal(options: GenieSealOptions): Promise<Uint8Array> {
    const to = options.to;
    return sealEnvelope({
      secretKey: this.#secretKey,
      from: this.name,
      payload: toBytes(options.payload),
      ...(to !== undefined && {
        aud: Array.isArray(to) ? to.map(keyOf) : keyOf(to),
      }),
      ...(options.presents !== undefined && { presents: options.presents }),
      ...(options.timestamp !== undefined && { timestamp: options.timestamp }),
      ...(options.nonce !== undefined && { nonce: options.nonce }),
    });
  }

  /**
   * Open an envelope: verify signature, that it is addressed to me (when
   * directed), the expected sender (when given), freshness against my own
   * replay window, and the validity of everything presented. Throws on
   * any failure; what it returns, you may trust to be real. Whether it is
   * *sufficient* is your judgment.
   *
   * @example
   * const envelope = await me.open(bytes, { from: courierName });
   * const request = envelope.json<{ op: string }>();
   */
  async open(bytes: Uint8Array, options: GenieOpenOptions = {}): Promise<OpenedEnvelope> {
    const envelope = await verifyEnvelope(bytes, {
      recipient: this.name,
      window: this.#window,
      ...(options.requireAudience !== undefined && { requireAudience: options.requireAudience }),
      ...(options.now !== undefined && { now: options.now }),
    });
    if (options.from !== undefined && !equalBytes(envelope.from, keyOf(options.from))) {
      throw new EnvelopeError("envelope from an unexpected sender");
    }
    if (options.verifyPresents !== false && envelope.presents) {
      for (const att of envelope.presents) {
        await verifyAttestation(att, options.now !== undefined ? { now: options.now } : {});
      }
    }
    // Payload conveniences, non-enumerable so the envelope's own fields
    // stay exactly the wire's.
    return Object.defineProperties(envelope as OpenedEnvelope, {
      text: { value: () => untext.decode(envelope.payload) },
      json: { value: () => JSON.parse(untext.decode(envelope.payload)) },
    });
  }

  /** Grant a capability: subject may ask this of me, in this scope. */
  grant(
    subject: KeyLike,
    options: TtlOptions & { scope: string[]; hops?: number },
  ): Promise<Capability> {
    return issueCapability({
      secretKey: this.#secretKey,
      issuer: this.name,
      subject: keyOf(subject),
      scope: options.scope,
      exp: expiryOf(options, nowSeconds()),
      hops: options.hops ?? 0,
    });
  }

  /**
   * Delegate a capability I hold, one hop down. Defaults are the parent's
   * scope and expiry with one fewer hop, and widening any of them is
   * refused here, at issuance, before any verifier has to.
   */
  async delegate(
    parent: Capability,
    subject: KeyLike,
    options: TtlOptions & { scope?: string[]; hops?: number } = {},
  ): Promise<Capability> {
    if (!equalBytes(parent.subject, this.name)) {
      throw new JinncoreError("only the capability's subject can delegate it");
    }
    if (parent.hops === 0) {
      throw new JinncoreError("capability is not delegable: hops is 0");
    }
    const scope = options.scope ?? parent.scope;
    const exp =
      options.exp !== undefined || options.ttl !== undefined
        ? expiryOf(options, nowSeconds())
        : parent.exp;
    const hops = options.hops ?? parent.hops - 1;
    const parentScope = new Set(parent.scope);
    if (!scope.every((entry) => parentScope.has(entry))) {
      throw new JinncoreError("delegation would widen scope");
    }
    if (exp > parent.exp) {
      throw new JinncoreError("delegation would extend expiry");
    }
    if (hops >= parent.hops) {
      throw new JinncoreError("delegation must strictly shrink hops");
    }
    return issueCapability({
      secretKey: this.#secretKey,
      issuer: this.name,
      subject: keyOf(subject),
      scope,
      exp,
      hops,
    });
  }

  /** Put my signature behind experience with another key. */
  testify(
    subject: KeyLike,
    options: TtlOptions & { body: string | Uint8Array },
  ): Promise<Testimony> {
    return issueTestimony({
      secretKey: this.#secretKey,
      issuer: this.name,
      subject: keyOf(subject),
      body: toBytes(options.body),
      exp: expiryOf(options, nowSeconds()),
    });
  }

  /** Countersign a membership offer addressed to me. */
  accept(offer: MembershipOffer): Promise<Membership> {
    return acceptMembership(offer, this.#secretKey);
  }

  /**
   * The secret key: whoever holds these bytes IS this genie. Store them
   * like the soul they are; restore with createGenie({ secretKey }).
   */
  export(): Uint8Array {
    return Uint8Array.from(this.#secretKey);
  }
}

/**
 * A society. A jinn has its own keypair and speaks only through it, so it
 * can do everything a genie can, plus admit members. There is no expel():
 * expulsion is silence where renewal used to be; simply stop admitting
 * the member into the next epoch.
 */
export class Jinn extends Genie {
  static override async create(options: CreateOptions = {}): Promise<Jinn> {
    const { secretKey, name } = await resolveIdentity(options);
    return new Jinn(secretKey, name, options.tolerance ?? 300, options.freshness);
  }

  /**
   * Sign a member in: half of the membership pair. It proves nothing
   * until the member accepts (countersigns) it.
   */
  admit(
    member: KeyLike,
    options: TtlOptions & { role: string; epoch?: number },
  ): Promise<MembershipOffer> {
    return grantMembership({
      secretKey: this.export(),
      issuer: this.name,
      subject: keyOf(member),
      role: options.role,
      epoch: options.epoch ?? 1,
      exp: expiryOf(options, nowSeconds()),
    });
  }
}

async function resolveIdentity(
  options: CreateOptions,
): Promise<{ secretKey: Uint8Array; name: Uint8Array }> {
  if (options.secretKey) {
    return {
      secretKey: Uint8Array.from(options.secretKey),
      name: await publicKeyOf(options.secretKey),
    };
  }
  const pair = await generateKeypair();
  return { secretKey: pair.secretKey, name: pair.publicKey };
}

/**
 * Kindle a genie: it mints its own keypair (or restores one you saved).
 *
 * @example
 * const alice = await createGenie();
 */
export function createGenie(options: CreateOptions = {}): Promise<Genie> {
  return Genie.create(options);
}

/**
 * Found a society: a jinn with its own key, able to admit members.
 *
 * @example
 * const guild = await createJinn();
 * const offer = await guild.admit(alice, { role: "scribe" });
 * const membership = await alice.accept(offer);
 */
export function createJinn(options: CreateOptions = {}): Promise<Jinn> {
  return Jinn.create(options);
}
