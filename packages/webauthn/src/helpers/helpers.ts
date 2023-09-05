// 來源：https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/browser/src/helpers

/* eslint-disable @typescript-eslint/ban-ts-comment */

import * as Ethers from "ethers";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

import { isoCBOR, isoBase64URL, isoUint8Array, isoCrypto } from "./iso";
import * as cose from "./cose";

import * as Asn1Ecc from "@peculiar/asn1-ecc";
import * as Asn1Schema from "@peculiar/asn1-schema";

export { isoCBOR, isoCrypto, isoBase64URL, isoUint8Array, cose };

// 設置基本 Passkey 參數
export const defaultPasskey = {
  // 是否要求查看安全金鑰的製造商和型號
  attestationConveyancePreference:
    "none" as WebauthnTypes.AttestationConveyancePreference,
  // This Relying Party will accept either an ES256 or RS256 credential, but prefers an ES256 credential.
  pubKeyCredAlgEs256: -7 as WebauthnTypes.COSEAlgorithmIdentifier,
  pubKeyCredAlgRs256: -257 as WebauthnTypes.COSEAlgorithmIdentifier,
  // Try to use UV if possible. This is also the default.
  pubKeyCredType: "public-key" as WebauthnTypes.PublicKeyCredentialType,
  // 驗證器是否可漫遊
  // 註 1：若使用虛擬驗證程式環境設定（Virtual Authenticator Environment）則必定是 cross-platform 驗證器
  // 註 2：若要透過 platform 驗證器註冊／登入，請關閉虛擬驗證程式環境設定（屬於 cross-platform），否則會卡住（若執行第 2 次註冊／登入，Relying Part 會被懷疑要來識別用戶）
  // https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client
  authenticatorAttachment:
    "cross-platform" as WebauthnTypes.AuthenticatorAttachment,
  // 參數 requireResidentKey 及 residentKeyRequirement 會要求驗證器是否支援可發現憑證（Supports resident keys = passkey）
  residentKeyRequirement: "required" as ResidentKeyRequirement,
  // 參數 userVerificationRequirement 會要求驗證器是否支援用戶驗證（Supports user verification）
  userVerificationRequirement:
    "required" as WebauthnTypes.UserVerificationRequirement,

  // 逾時
  timeout: 300000, // 5 minutes
  // Relying Party
  rpName: "imToken AA Server",
  // localhost
  rpId: `${window.location.hostname}`,
  // Make excludeCredentials check backwards compatible with credentials registered with U2F
  extensions: { poweredBy: "imToken Labs" },
  requireResidentKey: true,

  // Don’t re-register any authenticator that has one of these credentials
  excludeCredentials: [
    {
      id: "ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE=" as WebauthnTypes.Base64URLString,
      type: "public-key" as WebauthnTypes.PublicKeyCredentialType,
      transports: [
        "ble",
        "cable",
        "hybrid",
        "internal",
        "nfc",
        "smart-card",
        "usb",
      ] as WebauthnTypes.AuthenticatorTransportFuture[],
    },
    {
      id: "E/e1dhZc++mIsz4f9hb6NifAzJpF1V4mEtRlIPBiWdY=",
      type: "public-key",
    },
  ] as WebauthnTypes.PublicKeyCredentialDescriptorJSON[],
};

export enum InputId {
  userName,
  challengeCreate,
  challengeGet,
}

/**
 * COSE Key Types
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
export enum COSEKT {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
  Symmetric = 4,
  HSSLMS = 5,
  WalnutDSA = 6,
}

/**
 * COSE Key Common Parameters
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 */
export enum COSEKCP {
  kty = 1, // Mapping to COSEKT
  kid = 2,
  alg = 3, // Mapping to COSEALG
  key_ops = 4,
  BaseIV = 5,
}

/**
 * COSE Key Type Parameters
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */

export enum COSEKTP_OKP { // If COSEKCP.kty = COSEKT.OKP
  crv = -1, // Mapping to COSECRV
  x = -2,
  d = -4,
}
export enum COSEKTP_EC2 { // If COSEKCP.kty = COSEKT.EC2
  crv = -1, // Mapping to COSECRV
  x = -2,
  y = -3,
  d = -4,
}
export enum COSEKTP_RSA { // If COSEKCP.kty = COSEKT.RSA
  n = -1,
  e = -2,
  d = -3,
  p = -4,
  q = -5,
  dP = -6,
  dQ = -7,
  qInv = -8,
  other = -9,
  r_i = -10,
  d_i = -11,
  t_i = -12,
}
export enum COSEKTP_SYMMETRIC { // If COSEKCP.kty = COSEKT.Symmetric
  k = -1,
}
export enum COSEKTP_HSSLMS { // If COSEKCP.kty = COSEKT.HSSLMS
  pub = -1,
}
export enum COSEKTP_WALNUTDSA { // If COSEKCP.kty = COSEKT.WalnutDSA
  N = -1,
  q = -2,
  tvalues = -3,
  matrix1 = -4,
  permutation1 = -5,
  matrix2 = -6,
}

/**
 * COSE Algorithms
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export enum COSEALG { // COSEKCP.alg
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  ES256K = -47,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
  RS1 = -65535,
}

/**
 * COSE Elliptic Curves
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */

export enum COSECRV { // COSEKTP_XXX.crv
  P256 = 1,
  P384 = 2,
  P521 = 3,
  X25519 = 4,
  X448 = 5,
  Ed25519 = 6,
  Ed448 = 7,
  secp256k1 = 8,
}

export type COSEPublicKey = {
  // Getters
  get(key: COSEKCP.kty): COSEKT | undefined;
  get(key: COSEKCP.alg): COSEALG | undefined;
  // If COSEKCP.kty = COSEKT.EC2
  get(key: COSEKTP_EC2.crv): COSECRV | undefined;
  get(key: COSEKTP_EC2.x): Uint8Array | undefined;
  get(key: COSEKTP_EC2.y): Uint8Array | undefined;

  // Setters
  set(key: COSEKCP.kty, value: COSEKT): void;
  set(key: COSEKCP.alg, value: COSEALG): void;
  // If COSEKCP.kty = COSEKT.EC2
  set(key: COSEKTP_EC2.crv, value: COSECRV): void;
  set(key: COSEKTP_EC2.x, value: Uint8Array): void;
  set(key: COSEKTP_EC2.y, value: Uint8Array): void;
};

export const log = (name: string, value: any) => {
  let jsonString: string;
  try {
    jsonString = JSON.stringify(value, null, 2);
  } catch (e) {
    console.log(`${name}: ${value.toString()}`);
    return;
  }
  console.log(`${name}: ${jsonString}`);
};

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
export function decodeAuthenticatorExtensions(
  extensionData: Uint8Array
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
  let toCBOR: Map<string, unknown>;
  try {
    toCBOR = isoCBOR.decodeFirst(extensionData);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding authenticator extensions: ${_err.message}`);
  }

  return convertMapToObjectDeep(toCBOR);
}

export type AuthenticationExtensionsAuthenticatorOutputs = {
  devicePubKey?: DevicePublicKeyAuthenticatorOutput;
  uvm?: UVMAuthenticatorOutput;
};

export type DevicePublicKeyAuthenticatorOutput = {
  dpk?: Uint8Array;
  sig?: string;
  nonce?: Uint8Array;
  scope?: Uint8Array;
  aaguid?: Uint8Array;
};

// TODO: Need to verify this format
// https://w3c.github.io/webauthn/#sctn-uvm-extension.
export type UVMAuthenticatorOutput = {
  uvm?: Uint8Array[];
};

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = isoBase64URL.toString(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  return clientData;
}

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: {
    id?: string;
    status: "present" | "supported" | "not-supported";
  };
};

/**
 * CBOR-encoded extensions can be deeply-nested Maps, which are too deep for a simple
 * `Object.entries()`. This method will recursively make sure that all Maps are converted into
 * basic objects.
 */
function convertMapToObjectDeep(input: Map<string, unknown>): {
  [key: string]: unknown;
} {
  const mapped: { [key: string]: unknown } = {};

  for (const [key, value] of input) {
    if (value instanceof Map) {
      mapped[key] = convertMapToObjectDeep(value);
    } else {
      mapped[key] = value;
    }
  }

  return mapped;
}

/**
 * Prepare a DataView we can slice our way around in as we parse the bytes in a Uint8Array
 */
export function toDataView(array: Uint8Array): DataView {
  return new DataView(array.buffer, array.byteOffset, array.length);
}

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export function parseAuthenticatorData(
  authData: Uint8Array
): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`
    );
  }

  let pointer = 0;
  const dataView = toDataView(authData);

  const rpIdHash = authData.slice(pointer, (pointer += 32));

  const flagsBuf = authData.slice(pointer, (pointer += 1));
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array | undefined = undefined;
  let credentialID: Uint8Array | undefined = undefined;
  let credentialPublicKey: Uint8Array | undefined = undefined;
  let credentialPublicKeyKty: number | undefined = undefined;
  let credentialPublicKeyAlg: number | undefined = undefined;
  let credentialPublicKeyCrv: number | undefined = undefined;
  let credentialPublicKeyX: Uint8Array | undefined = undefined;
  let credentialPublicKeyY: Uint8Array | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, (pointer += 16));

    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    credentialID = authData.slice(pointer, (pointer += credIDLen));

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = isoCBOR.decodeFirst<COSEPublicKey>(
      authData.slice(pointer)
    );

    credentialPublicKeyKty = firstDecoded.get(COSEKCP.kty);
    credentialPublicKeyAlg = firstDecoded.get(COSEKCP.alg);
    credentialPublicKeyCrv = firstDecoded.get(COSEKTP_EC2.crv);
    credentialPublicKeyX = firstDecoded.get(COSEKTP_EC2.x);
    credentialPublicKeyY = firstDecoded.get(COSEKTP_EC2.y);

    const firstEncoded = Uint8Array.from(isoCBOR.encode(firstDecoded));

    credentialPublicKey = firstEncoded;
    pointer += firstEncoded.byteLength;
  }

  let extensionsData: AuthenticationExtensionsAuthenticatorOutputs | undefined =
    undefined;
  let extensionsDataBuffer: Uint8Array | undefined = undefined;

  if (flags.ed) {
    const firstDecoded = isoCBOR.decodeFirst(authData.slice(pointer));
    extensionsDataBuffer = Uint8Array.from(isoCBOR.encode(firstDecoded));
    extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
    pointer += extensionsDataBuffer.byteLength;
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength > pointer) {
    throw new Error("Leftover bytes detected while parsing authenticator data");
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    credentialPublicKeyKty,
    credentialPublicKeyAlg,
    credentialPublicKeyCrv,
    credentialPublicKeyX,
    credentialPublicKeyY,
    extensionsData,
    extensionsDataBuffer,
  };
}

export type ParsedAuthenticatorData = {
  rpIdHash: Uint8Array;
  flagsBuf: Uint8Array;
  flags: {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Uint8Array;
  aaguid?: Uint8Array;
  credentialID?: Uint8Array;
  credentialPublicKey?: Uint8Array;
  credentialPublicKeyKty?: number;
  credentialPublicKeyAlg?: number;
  credentialPublicKeyCrv?: number;
  credentialPublicKeyX?: Uint8Array;
  credentialPublicKeyY?: Uint8Array;
  extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
  extensionsDataBuffer?: Uint8Array;
};

/**
 * Convert the given array buffer into a Base64URL-encoded string. Ideal for converting various
 * credential response ArrayBuffers to string for sending back to the server as JSON.
 *
 * Helper method to compliment `base64URLStringToBuffer`
 */
export function bufferToBase64URLString(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = "";

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Convert from a Base64URL-encoded string to an Array Buffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials
 *
 * Helper method to compliment `bufferToBase64URLString`
 */
export function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
  // Convert from Base64URL to Base64
  const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  /**
   * Pad with '=' until it's a multiple of four
   * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
   * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
   * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
   * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
   */
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, "=");

  // Convert to a binary string
  const binary = atob(padded);

  // Convert binary string to buffer
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(
  attestationObject: Uint8Array
): AttestationObject {
  return isoCBOR.decodeFirst<AttestationObject>(attestationObject);
}

export type AttestationFormat =
  | "fido-u2f"
  | "packed"
  | "android-safetynet"
  | "android-key"
  | "tpm"
  | "apple"
  | "none";

export type AttestationObject = {
  get(key: "fmt"): AttestationFormat;
  get(key: "attStmt"): AttestationStatement;
  get(key: "authData"): Uint8Array;
};

/**
 * `AttestationStatement` will be an instance of `Map`, but these keys help make finite the list of
 * possible values within it.
 */
export type AttestationStatement = {
  get(key: "sig"): Uint8Array | undefined;
  get(key: "x5c"): Uint8Array[] | undefined;
  get(key: "response"): Uint8Array | undefined;
  get(key: "alg"): number | undefined;
  get(key: "ver"): string | undefined;
  get(key: "certInfo"): Uint8Array | undefined;
  get(key: "pubArea"): Uint8Array | undefined;
  // `Map` properties
  readonly size: number;
};

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export const parseEC2Signature = (sig: Uint8Array) => {
  const parsedSignature = Asn1Schema.AsnParser.parse(
    sig,
    Asn1Ecc.ECDSASigValue
  );

  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  return {
    r: rBytes,
    s: sBytes,
  };
};

/**
 * Determine if the DER-specific `00` byte at the start of an ECDSA signature byte sequence
 * should be removed based on the following logic:
 *
 * "If the leading byte is 0x0, and the the high order bit on the second byte is not set to 0,
 * then remove the leading 0x0 byte"
 */
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export const base64URLStringToHex = (base64URLString: string) => {
  return `0x${isoUint8Array.toHex(isoBase64URL.toBuffer(base64URLString))}`;
};

export const hexToBase64URLString = (hexString: string) => {
  // 去掉 0x 前綴後再轉換
  return isoBase64URL.fromBuffer(isoUint8Array.fromHex(hexString.slice(2)));
};

export const hexToUTF8String = (hexString: string) => {
  return `${isoUint8Array.toUTF8String(
    isoUint8Array.fromHex(hexString.slice(2))
  )}`;
};

export const utf8StringToHex = (utf8String: string) => {
  // 去掉 0x 前綴後再轉換
  return `0x${isoUint8Array.toHex(isoUint8Array.fromUTF8String(utf8String))}`;
};

// clientDataJSON 有 2 種格式，在解析時需注意：
// 1.
// {"type":"webauthn.get","challenge":"xxx","origin":"http://localhost:5173","crossOrigin":false}
// 2.
// {"type":"webauthn.get","challenge":"xxx","origin":"http://localhost:5173","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}
//
export const splitClientDataJSONUtf8 = (
  clientDataJSON: string
  // origin: string
) => {
  // example: origin = "http://localhost:5173"
  const clientDataJSONPreLength = `{"type":"webauthn.get","challenge":"`.length;
  const bytes32ToBase64Length = hexToBase64URLString(
    Ethers.keccak256("0x1234")
  ).length;
  // const clientDataJSONPostLength = `","origin":"${origin}","crossOrigin":false}`
  //   .length;
  return {
    clientDataJSONPre: clientDataJSON.slice(0, clientDataJSONPreLength),
    clientDataJSONChallenge: clientDataJSON.slice(
      clientDataJSONPreLength,
      clientDataJSONPreLength + bytes32ToBase64Length
    ),
    clientDataJSONPost: clientDataJSON.slice(
      clientDataJSONPreLength + bytes32ToBase64Length
      // , clientDataJSONPreLength + bytes32Length + clientDataJSONPostLength
    ),
  };
};

/**
 * Returns hash digest of the given data, using the given algorithm when provided. Defaults to using
 * SHA-256.
 */
export function toHash(
  data: Uint8Array | string,
  algorithm: COSEALG = -7
): Promise<Uint8Array> {
  if (typeof data === "string") {
    data = isoUint8Array.fromUTF8String(data);
  }

  const digest = isoCrypto.digest(data, algorithm);

  return digest;
}

// export const parsingAuthenticatorData = async (attestationObject: string) => {
//   const attestationObjectBuffer = base64URLStringToBuffer(attestationObject);

//   const decodedAttestationObject = await Cbor.decode(attestationObjectBuffer);

//   console.log(
//     `decodedAttestationObject: ${JSON.stringify(
//       decodedAttestationObject,
//       null,
//       2
//     )}`
//   );

//   const authData = decodedAttestationObject.authData.data as Buffer;
//   //as Uint8Array;

//   console.log(`authData: ${authData}`);

//   // get the length of the credential ID
//   const dataView = new DataView(new ArrayBuffer(2));
//   const idLenBytes = authData.slice(53, 55);
//   idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
//   const credentialIdLength = dataView.getUint16(1);

//   console.log(`credentialIdLength: ${credentialIdLength}`);

//   // get the credential ID
//   const credentialId = authData.slice(55, 55 + credentialIdLength);

//   // console.log(`credentialId: ${JSON.stringify(credentialId, null, 2)}`);

//   // get the public key object
//   const publicKeyBytes = authData.slice(55 + credentialIdLength);

//   // the publicKeyBytes are encoded again as CBOR
//   const publicKeyObject = await Cbor.decode(publicKeyBytes.buffer);

//   console.log(`publicKeyObject: ${JSON.stringify(publicKeyObject, null, 2)}`);
// };
