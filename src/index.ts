/**
 * jinncore — the Jinn protocol core.
 *
 * This module is the primitives layer (also importable as
 * "jinncore/wire"): canonical bytes, identity, envelopes, attestations.
 * The friendlier high-level layer will live at the package root when it
 * lands; the primitives stay importable from "jinncore/wire" permanently.
 */

export { JinncoreError } from "./errors.js";

export { encodeWire, decodeWire, WireEncodeError, WireDecodeError } from "./cbor.js";
export type { WireValue } from "./cbor.js";

export {
  generateKeypair,
  publicKeyOf,
  sign,
  verifySignature,
  PUBLIC_KEY_LENGTH,
  SECRET_KEY_LENGTH,
  SIGNATURE_LENGTH,
} from "./identity.js";
export type { Keypair } from "./identity.js";

export {
  sealEnvelope,
  verifyEnvelope,
  FreshnessWindow,
  EnvelopeError,
  WIRE_VERSION,
  NONCE_LENGTH_DEFAULT,
  NONCE_LENGTH_MIN,
  NONCE_LENGTH_MAX,
} from "./envelope.js";
export type { Envelope, Fresh, SealOptions, VerifyOptions } from "./envelope.js";

export { sha256 } from "./digest.js";
export { compareBytes, equalBytes, toHex, fromHex } from "./bytes.js";

export {
  issueCapability,
  issueTestimony,
  grantMembership,
  acceptMembership,
  parseAttestation,
  verifyAttestation,
  verifyDelegationChain,
  AttestationError,
} from "./attestation.js";
export type {
  Attestation,
  AttestationKind,
  Capability,
  Testimony,
  Membership,
  MembershipOffer,
  DelegatedGrant,
  IssueCapabilityOptions,
  IssueTestimonyOptions,
  GrantMembershipOptions,
  VerifyAttestationOptions,
} from "./attestation.js";
