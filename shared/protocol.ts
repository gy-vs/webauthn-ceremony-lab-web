/**
 * Wire types for the lab API and for exportable ceremony records.
 * All binary fields are base64url (no padding) strings.
 */

export type CeremonyKind = 'registration' | 'authentication';
export type Transport = 'internal' | 'usb' | 'nfc' | 'ble' | 'hybrid';
export type AttestationPreference = 'none' | 'indirect' | 'direct';
export type ResidentKeyRequirement = 'discouraged' | 'preferred' | 'required';
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';
export type AttestationStatementFormat = 'none' | 'packed-self';

export interface PublicKeyCredentialUserEntity {
  id: string; // base64url user handle
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialRpEntity {
  id: string;
  name: string;
}

export interface PublicKeyCredentialParameters {
  type: 'public-key';
  alg: number; // -7 = ES256
}

/* ---------------- Registration options ---------------- */

export interface RegistrationOptions {
  challenge: string;
  timeout: number;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  attestation: AttestationPreference;
  authenticatorSelection?: {
    residentKey: ResidentKeyRequirement;
    requireResidentKey: boolean;
    userVerification: UserVerificationRequirement;
  };
  excludeCredentials: { id: string; type: 'public-key'; transports: Transport[] }[];
  /** Echoed to the UI so it is visible which origin the server will accept. */
  expectedOrigin: string;
  expectedRpId: string;
  expiresAt: number;
}

export interface AuthenticatorAttestationResponsePayload {
  clientDataJSON: string;
  attestationObject: string;
  /** Synthetic transports produced by the test authenticator. */
  transports: Transport[];
  /** Lab-only public echo so the UI can show which flags were set. */
  authenticatorFlags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
}

export interface RegistrationResult {
  credentialId: string;
  credentialIdHex: string;
  publicKeyJwk: JsonWebKey;
  signCount: number;
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  attestationFormat: AttestationStatementFormat;
  residentKey: boolean;
  userVerified: boolean;
  createdAt: number;
}

/* ---------------- Authentication options ---------------- */

export interface AuthenticationOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials: { id: string; type: 'public-key'; transports: Transport[] }[];
  userVerification: UserVerificationRequirement;
  expectedOrigin: string;
  expectedRpId: string;
  expiresAt: number;
}

export interface AuthenticatorAssertionResponsePayload {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string | null;
  authenticatorFlags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
}

export interface AuthenticationResult {
  credentialId: string;
  userHandle: string | null;
  signCount: number;
  previousSignCount: number;
  cloneWarning: boolean;
  userVerified: boolean;
  authenticatedAt: number;
}

/* ---------------- API envelopes ---------------- */

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface CredentialSummary {
  credentialId: string;
  credentialIdHex: string;
  user: PublicKeyCredentialUserEntity;
  signCount: number;
  residentKey: boolean;
  userVerified: boolean;
  cloneDetected: boolean;
  createdAt: number;
  lastUsedAt: number | null;
  publicKeyJwk: JsonWebKey;
  rpId: string;
}

/* ---------------- Exportable ceremony record ---------------- */

/**
 * A ceremony record captures the complete inputs and outputs of one
 * registration or authentication so it can be re-imported and re-checked.
 * It deliberately contains NO private key material: the attestation object
 * embeds only the public COSE key, and assertions carry only a signature.
 */
export interface CeremonyRecord {
  format: 'webauthn-ceremony-lab/record';
  formatVersion: 1;
  exportedAt: number;
  ceremony: CeremonyKind;
  rp: PublicKeyCredentialRpEntity;
  expectedOrigin: string;
  options: RegistrationOptions | AuthenticationOptions;
  /** Raw authenticator response fields (base64url). */
  response: AuthenticatorAttestationResponsePayload | AuthenticatorAssertionResponsePayload;
  /** Server verdict at the time of export. */
  verdict:
    | { ok: true; result: RegistrationResult | AuthenticationResult }
    | { ok: false; errorCode: string; message: string };
  /** Notes added by the scenario (e.g. "wrong origin", "counter rewound"). */
  scenarioNotes: string[];
}
