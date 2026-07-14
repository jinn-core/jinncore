/**
 * Attestation (SPEC.md §6): the protocol's single instrument of standing.
 *
 * Three species, one frame: a signed, expiring statement by `issuer` about
 * `subject`. Membership alone is a matched pair: the jinn signs the
 * statement's canonical bytes, the member countersigns their SHA-256
 * digest, so the halves cannot be re-paired and neither half is forgeable
 * alone.
 *
 * This module verifies validity (signatures, expiry, chain attenuation),
 * never sufficiency: whether a valid attestation should convince anyone is
 * the counterparty gate's own judgment, above the waist.
 */

import { encodeWire, type WireValue } from "./cbor.js";
import { compareBytes, equalBytes } from "./bytes.js";
import { sha256 } from "./digest.js";
import { JinncoreError } from "./errors.js";
import { isBytes, isPlainMap, isUint, requireKeys } from "./shape.js";
import {
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  publicKeyOf,
  sign,
  verifySignature,
} from "./identity.js";

export class AttestationError extends JinncoreError {}

export type AttestationKind = "capability" | "testimony" | "membership";

/** A grant: you may ask this of me, in this scope, until this time. */
export interface Capability {
  kind: "capability";
  issuer: Uint8Array;
  subject: Uint8Array;
  exp: number;
  /** Uninterpreted strings; strictly ascending, unique, non-empty. */
  scope: string[];
  /** Delegation budget; 0 means not delegable. */
  hops: number;
  sig: Uint8Array;
}

/** Signed experience: I dealt with this key, and this is what happened. */
export interface Testimony {
  kind: "testimony";
  issuer: Uint8Array;
  subject: Uint8Array;
  exp: number;
  /** Opaque; meaning is convention between genies, never protocol law. */
  body: Uint8Array;
  sig: Uint8Array;
}

/** A membership grant awaiting the member's countersignature. */
export interface MembershipOffer {
  kind: "membership";
  issuer: Uint8Array;
  subject: Uint8Array;
  exp: number;
  role: string;
  epoch: number;
  sig: Uint8Array;
}

/** The matched pair: only this proves belonging. */
export interface Membership extends MembershipOffer {
  /** By `subject`, over SHA-256 of the statement's canonical bytes. */
  memberSig: Uint8Array;
}

export type Attestation = Capability | Testimony | Membership;

type Statement =
  | Omit<Capability, "sig">
  | Omit<Testimony, "sig">
  | Omit<MembershipOffer, "sig">;

/**
 * The statement is the attestation minus its signatures. Its canonical
 * bytes are what the issuer signs and what the member's countersignature
 * digests.
 */
function statementBytes(att: Statement): Uint8Array {
  const stmt: { [key: string]: WireValue } = {
    kind: att.kind,
    issuer: att.issuer,
    subject: att.subject,
    exp: att.exp,
  };
  if (att.kind === "capability") {
    stmt.scope = att.scope;
    stmt.hops = att.hops;
  } else if (att.kind === "testimony") {
    stmt.body = att.body;
  } else {
    stmt.role = att.role;
    stmt.epoch = att.epoch;
  }
  return encodeWire(stmt);
}

// --- field validation ---------------------------------------------------

const utf8 = new TextEncoder();

function compareText(a: string, b: string): number {
  return compareBytes(utf8.encode(a), utf8.encode(b));
}

function assertKey(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== PUBLIC_KEY_LENGTH) {
    throw new AttestationError(`${name} must be a 32-byte key`);
  }
}

function assertUint(value: unknown, name: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new AttestationError(`${name} must be a non-negative integer`);
  }
}

function assertScope(scope: unknown): asserts scope is string[] {
  if (!Array.isArray(scope) || scope.length === 0) {
    throw new AttestationError("scope must be a non-empty array");
  }
  for (const entry of scope) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new AttestationError("scope entries must be non-empty text");
    }
  }
  for (let i = 1; i < scope.length; i++) {
    if (compareText(scope[i - 1] as string, scope[i] as string) >= 0) {
      throw new AttestationError("scope must be strictly ascending and unique");
    }
  }
}

function assertRole(role: unknown): asserts role is string {
  if (typeof role !== "string" || role.length === 0) {
    throw new AttestationError("role must be non-empty text");
  }
}

// --- issuance -----------------------------------------------------------

export interface IssueCapabilityOptions {
  secretKey: Uint8Array;
  /** Issuer's public key; derived from secretKey when omitted. */
  issuer?: Uint8Array;
  subject: Uint8Array;
  exp: number;
  scope: string[];
  hops: number;
}

/**
 * Grant a capability: subject may ask this of the issuer, in this scope,
 * until this time, delegable `hops` more times.
 *
 * @example
 * const cap = await issueCapability({
 *   secretKey: me.secretKey,
 *   subject: friend.publicKey,
 *   scope: ["orders/read"],
 *   exp: now + 3600,
 *   hops: 0,
 * });
 */
export async function issueCapability(options: IssueCapabilityOptions): Promise<Capability> {
  const issuer = options.issuer ?? (await publicKeyOf(options.secretKey));
  assertKey(issuer, "issuer");
  assertKey(options.subject, "subject");
  assertUint(options.exp, "exp");
  assertUint(options.hops, "hops");
  assertScope(options.scope);
  const stmt: Omit<Capability, "sig"> = {
    kind: "capability",
    issuer,
    subject: options.subject,
    exp: options.exp,
    scope: [...options.scope],
    hops: options.hops,
  };
  const sig = await sign(statementBytes(stmt), options.secretKey);
  return { ...stmt, sig };
}

export interface IssueTestimonyOptions {
  secretKey: Uint8Array;
  issuer?: Uint8Array;
  subject: Uint8Array;
  exp: number;
  body: Uint8Array;
}

/**
 * Put your signature behind experience: I dealt with this key, and this
 * is what happened. The body is opaque to the protocol.
 */
export async function issueTestimony(options: IssueTestimonyOptions): Promise<Testimony> {
  const issuer = options.issuer ?? (await publicKeyOf(options.secretKey));
  assertKey(issuer, "issuer");
  assertKey(options.subject, "subject");
  assertUint(options.exp, "exp");
  if (!(options.body instanceof Uint8Array)) {
    throw new AttestationError("body must be a byte string");
  }
  const stmt: Omit<Testimony, "sig"> = {
    kind: "testimony",
    issuer,
    subject: options.subject,
    exp: options.exp,
    body: options.body,
  };
  const sig = await sign(statementBytes(stmt), options.secretKey);
  return { ...stmt, sig };
}

export interface GrantMembershipOptions {
  /** The jinn's secret key. */
  secretKey: Uint8Array;
  /** The jinn's public key; derived from secretKey when omitted. */
  issuer?: Uint8Array;
  /** The member being admitted. */
  subject: Uint8Array;
  role: string;
  epoch: number;
  exp: number;
}

/**
 * The jinn's half of the membership pair: signs the statement "this key
 * is ours, in this role, for this epoch, until this expiry". Proves
 * nothing alone; the member must accept (countersign) it.
 *
 * @example
 * const offer = await grantMembership({
 *   secretKey: jinn.secretKey,
 *   subject: member.publicKey,
 *   role: "scribe",
 *   epoch: 1,
 *   exp: now + 30 * 86400,
 * });
 * const membership = await acceptMembership(offer, member.secretKey);
 */
export async function grantMembership(options: GrantMembershipOptions): Promise<MembershipOffer> {
  const issuer = options.issuer ?? (await publicKeyOf(options.secretKey));
  assertKey(issuer, "issuer");
  assertKey(options.subject, "subject");
  assertUint(options.exp, "exp");
  assertUint(options.epoch, "epoch");
  assertRole(options.role);
  const stmt: Omit<MembershipOffer, "sig"> = {
    kind: "membership",
    issuer,
    subject: options.subject,
    exp: options.exp,
    role: options.role,
    epoch: options.epoch,
  };
  const sig = await sign(statementBytes(stmt), options.secretKey);
  return { ...stmt, sig };
}

/**
 * The member's half: countersigns SHA-256 of the exact statement. Refuses
 * to countersign an offer that is not addressed to this key or whose
 * issuer signature does not verify: never sign what you did not check.
 */
export async function acceptMembership(
  offer: MembershipOffer,
  secretKey: Uint8Array,
): Promise<Membership> {
  const self = await publicKeyOf(secretKey);
  if (!equalBytes(offer.subject, self)) {
    throw new AttestationError("offer is not addressed to this key");
  }
  const stmt = statementBytes(offer);
  if (!(await verifySignature(offer.sig, stmt, offer.issuer))) {
    throw new AttestationError("offer signature does not verify");
  }
  const memberSig = await sign(await sha256(stmt), secretKey);
  return { ...offer, memberSig };
}

// --- parsing ------------------------------------------------------------

const COMMON_KEYS = ["kind", "issuer", "subject", "exp", "sig"];

/** Shape-check a decoded wire value as an attestation. No crypto. */
export function parseAttestation(value: WireValue): Attestation {
  if (!isPlainMap(value)) throw new AttestationError("attestation must be a map");
  const kind = value.kind;
  if (kind !== "capability" && kind !== "testimony" && kind !== "membership") {
    throw new AttestationError(`unknown attestation kind: ${String(kind)}`);
  }
  if (!isBytes(value.issuer, PUBLIC_KEY_LENGTH)) throw new AttestationError("issuer must be a 32-byte key");
  if (!isBytes(value.subject, PUBLIC_KEY_LENGTH)) throw new AttestationError("subject must be a 32-byte key");
  if (!isUint(value.exp)) throw new AttestationError("exp must be a non-negative integer");
  if (!isBytes(value.sig, SIGNATURE_LENGTH)) throw new AttestationError("sig must be a 64-byte signature");

  const common = { issuer: value.issuer, subject: value.subject, exp: value.exp, sig: value.sig };

  switch (kind) {
    case "capability": {
      requireKeys(value, [...COMMON_KEYS, "scope", "hops"], [], AttestationError);
      assertScope(value.scope);
      assertUint(value.hops, "hops");
      return { kind, ...common, scope: [...value.scope], hops: value.hops };
    }
    case "testimony": {
      requireKeys(value, [...COMMON_KEYS, "body"], [], AttestationError);
      if (!isBytes(value.body)) throw new AttestationError("body must be a byte string");
      return { kind, ...common, body: value.body };
    }
    case "membership": {
      requireKeys(value, [...COMMON_KEYS, "role", "epoch", "memberSig"], [], AttestationError);
      assertRole(value.role);
      assertUint(value.epoch, "epoch");
      if (!isBytes(value.memberSig, SIGNATURE_LENGTH)) {
        throw new AttestationError("memberSig must be a 64-byte signature");
      }
      return {
        kind,
        ...common,
        role: value.role,
        epoch: value.epoch,
        memberSig: value.memberSig,
      };
    }
  }
}

// --- verification -------------------------------------------------------

export interface VerifyAttestationOptions {
  /** The verifier's clock, seconds; defaults to this machine's clock. */
  now?: number;
}

/**
 * Verify one attestation: expiry on the verifier's clock, issuer signature
 * over the statement, and for membership the member's countersignature
 * over the statement's digest. Throws AttestationError on any failure.
 *
 * @example
 * await verifyAttestation(membership); // throws if forged, re-paired, or expired
 */
export async function verifyAttestation(
  att: Attestation,
  options: VerifyAttestationOptions = {},
): Promise<void> {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (now > att.exp) throw new AttestationError("attestation expired");

  const stmt = statementBytes(att);
  if (!(await verifySignature(att.sig, stmt, att.issuer))) {
    throw new AttestationError("issuer signature does not verify");
  }
  if (att.kind === "membership") {
    if (!isBytes((att as Membership).memberSig, SIGNATURE_LENGTH)) {
      throw new AttestationError("membership without countersignature proves nothing");
    }
    if (!(await verifySignature(att.memberSig, await sha256(stmt), att.subject))) {
      throw new AttestationError("member countersignature does not verify");
    }
  }
}

/** What a valid delegation chain amounts to for its final holder. */
export interface DelegatedGrant {
  /** The root issuer whose resource this chain draws on. */
  issuer: Uint8Array;
  /** The final holder. */
  subject: Uint8Array;
  scope: string[];
  exp: number;
  hops: number;
}

/**
 * Verify a delegation chain, root first. Each link must be a valid
 * capability; each delegation must be issued by the previous subject and
 * strictly attenuate: subset scope, no later expiry, strictly fewer hops.
 *
 * @example
 * const grant = await verifyDelegationChain([rootCap, delegatedCap]);
 * // grant.subject is the final holder; grant.scope is what they may ask
 */
export async function verifyDelegationChain(
  chain: Capability[],
  options: VerifyAttestationOptions = {},
): Promise<DelegatedGrant> {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new AttestationError("delegation chain is empty");
  }
  for (const link of chain) {
    if (link.kind !== "capability") {
      throw new AttestationError("delegation chain links must be capabilities");
    }
    await verifyAttestation(link, options);
  }
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]!;
    const child = chain[i]!;
    if (!equalBytes(child.issuer, parent.subject)) {
      throw new AttestationError("chain link not issued by the previous subject");
    }
    const parentScope = new Set(parent.scope);
    if (!child.scope.every((entry) => parentScope.has(entry))) {
      throw new AttestationError("delegation widens scope");
    }
    if (child.exp > parent.exp) {
      throw new AttestationError("delegation extends expiry");
    }
    if (child.hops >= parent.hops) {
      throw new AttestationError("delegation must strictly shrink hops");
    }
  }
  const last = chain[chain.length - 1]!;
  return {
    issuer: chain[0]!.issuer,
    subject: last.subject,
    scope: [...last.scope],
    exp: last.exp,
    hops: last.hops,
  };
}
