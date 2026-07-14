/**
 * jinncore/wire — the primitives layer: canonical bytes, identity,
 * envelopes, attestations. Everything here mirrors SPEC.md exactly. The
 * friendly actor layer (createGenie / createJinn) lives at the package
 * root and is built entirely on these exports.
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
