export { encode, decode, WireEncodeError, WireDecodeError } from "./cbor.js";
export type { WireValue } from "./cbor.js";

export {
  mintKeypair,
  publicKeyOf,
  sign,
  verifySignature,
  PUBLIC_KEY_LENGTH,
  SECRET_KEY_LENGTH,
  SIGNATURE_LENGTH,
} from "./identity.js";
export type { Keypair } from "./identity.js";

export {
  seal,
  verify,
  FreshnessWindow,
  EnvelopeError,
  WIRE_VERSION,
  NONCE_LENGTH_DEFAULT,
  NONCE_LENGTH_MIN,
  NONCE_LENGTH_MAX,
} from "./envelope.js";
export type { Envelope, Fresh, SealOptions, VerifyOptions } from "./envelope.js";

export { sha256 } from "./digest.js";
export { compareBytes, equalBytes, toHex } from "./bytes.js";

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
