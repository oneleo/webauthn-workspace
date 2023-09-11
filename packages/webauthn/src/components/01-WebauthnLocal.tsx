import * as React from "react";
import * as Ethers from "ethers";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";
import * as WebauthnBrowser from "@simplewebauthn/browser";
import * as Axios from "axios";

import * as Helpers from "../helpers/helpers";
import { log, defaultPasskey, InputId } from "../helpers/helpers";

const debug = true;
const bananaDebug = false;

export const WebauthnLocal = () => {
  const [user, setUser] = React.useState<string>("user");
  const [challengeCreate, setChallengeCreate] = React.useState<string>(
    Helpers.hexToBase64URLString(Ethers.keccak256("0x123456"))
  );
  const [challengeGet, setChallengeGet] = React.useState<string>(
    Helpers.hexToBase64URLString(Ethers.keccak256("0x456789"))
  );
  const [authAttach, setAuthAttach] =
    React.useState<WebauthnTypes.AuthenticatorAttachment>(
      defaultPasskey.authenticatorAttachment
    );
  const [authAttachChecked, setAuthAttachChecked] = React.useState<boolean>(
    false // false = "cross-platform", true = "platform"
  );

  // ------------------------------
  // --- Create Passkey Handler ---
  // ------------------------------

  const handleCreatePasskeyDepList: React.DependencyList = [
    user,
    challengeCreate,
    authAttach,
  ];

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-registration
  const handleCreatePasskey = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeCreate;

    // User
    const userDisplayName = user;
    const name = user.toLowerCase().replace(/[^\w]/g, "");
    const id = Math.floor(
      Math.random() * (Math.floor(999999999) - Math.ceil(3333) + 1) +
        Math.ceil(3333)
    )
      .toString()
      .padStart(9, "0");
    const userId = `${name}-${id}`;
    const userName = `${name}-${id}@${defaultPasskey.rpId}`;

    const registrationResponseJSON: WebauthnTypes.RegistrationResponseJSON =
      await WebauthnBrowser.startRegistration({
        rp: {
          name: defaultPasskey.rpName,
          id: defaultPasskey.rpId,
        },
        user: {
          id: userId,
          name: userName,
          displayName: userDisplayName,
        },
        challenge: challengeBase64,
        pubKeyCredParams: [
          {
            alg: defaultPasskey.pubKeyCredAlgEs256,
            type: defaultPasskey.pubKeyCredType,
          },
          {
            alg: defaultPasskey.pubKeyCredAlgRs256,
            type: defaultPasskey.pubKeyCredType,
          },
        ],
        timeout: defaultPasskey.timeout,
        excludeCredentials: defaultPasskey.excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: authAttach,
          requireResidentKey: defaultPasskey.requireResidentKey,
          residentKey: defaultPasskey.residentKeyRequirement,
          userVerification: defaultPasskey.userVerificationRequirement,
        },
        attestation: defaultPasskey.attestationConveyancePreference,
        extensions: defaultPasskey.extensions,
      } as WebauthnTypes.PublicKeyCredentialCreationOptionsJSON);

    // 取得 credentialIdHex
    const idHex = Helpers.base64URLStringToHex(registrationResponseJSON.id);

    const attestationObjectBase64 =
      registrationResponseJSON.response.attestationObject;

    // Parse attestationObject
    const parsedAttestationObject = Helpers.decodeAttestationObject(
      Helpers.isoBase64URL.toBuffer(attestationObjectBase64)
    );

    // Parse authenticatorData
    const parsedAuthData = Helpers.parseAuthenticatorData(
      parsedAttestationObject.get("authData")
    );

    // 取得 credentialPublicKeyY
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyXBase64 = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );

    const credentialPublicKeyXHex = Helpers.base64URLStringToHex(
      credentialPublicKeyXBase64
    );

    // 取得 credentialPublicKeyY
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyYBase64 = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );

    const credentialPublicKeyYHex = Helpers.base64URLStringToHex(
      credentialPublicKeyYBase64
    );

    if (debug) {
      console.warn(`+++ Create Passkey +++`);
      //   log("Registration Response JSON", registrationResponseJSON);
      log("* idBase64", registrationResponseJSON.id);
      log("idHex", idHex);
      log("rawIdBase64", registrationResponseJSON.rawId);
      log("typeUtf8", registrationResponseJSON.type);
      log(
        "clientExtensionResultsUtf8",
        registrationResponseJSON.clientExtensionResults
      );
      log(
        "authenticatorAttachmentUtf8",
        registrationResponseJSON.authenticatorAttachment
      );
      log(
        "publicKeyAlgorithm",
        registrationResponseJSON.response.publicKeyAlgorithm
      );
      console.log(
        `+ The algorithm list: https://www.iana.org/assignments/cose/cose.xhtml#algorithms`
      );
      log("attestationObjectBase64", attestationObjectBase64);

      const fmt = parsedAttestationObject.get("fmt");
      log("attestationObject > fmt", fmt);

      const attStmt = parsedAttestationObject.get("attStmt");
      log("attestationObject > attStmt", attStmt);

      const credentialIDBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.credentialID!
      );
      log(
        "attestationObject > authData > credentialIDBase64",
        credentialIDBase64
      );
      log(
        "attestationObject > authData > credentialPublicKeyXBase64",
        credentialPublicKeyXBase64
      );
      log(
        "* attestationObject > authData > credentialPublicKeyXHex",
        credentialPublicKeyXHex
      );
      log(
        "attestationObject > authData > credentialPublicKeyYBase64",
        credentialPublicKeyYBase64
      );
      log(
        "* attestationObject > authData > credentialPublicKeyYHex",
        credentialPublicKeyYHex
      );

      const aaguidBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.aaguid!
      );
      log("attestationObject > authData > aaguidBase64", aaguidBase64);

      const counter = parsedAuthData.counter;
      log("attestationObject > authData > counter", counter);

      const counterBufBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.counterBuf
      );
      log("attestationObject > authData > counterBufBase64", counterBufBase64);

      const credentialPublicKeyBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.credentialPublicKey!
      );
      log(
        "attestationObject > authData > credentialPublicKeyBase64",
        credentialPublicKeyBase64
      );

      const credentialPublicKeyAlg = parsedAuthData.credentialPublicKeyAlg!;
      log(
        "attestationObject > authData > credentialPublicKey > alg",
        credentialPublicKeyAlg
      );
      console.log(
        `+ The algorithm list: https://www.iana.org/assignments/cose/cose.xhtml#algorithms`
      );

      const credentialPublicKeyCrv = parsedAuthData.credentialPublicKeyCrv!;
      log(
        "attestationObject > authData > credentialPublicKey > crv",
        credentialPublicKeyCrv
      );
      console.log(
        `+ The elliptic curves list: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves`
      );

      const credentialPublicKeyKty = parsedAuthData.credentialPublicKeyKty!;
      log(
        "attestationObject > authData > credentialPublicKey > kty",
        credentialPublicKeyKty
      );
      console.log(
        `+ The key type list: https://www.iana.org/assignments/cose/cose.xhtml#key-type`
      );

      const extensionsData = parsedAuthData.extensionsData!;
      log("attestationObject > authData > extensionsData", extensionsData);

      const extensionsDataBufferBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.extensionsDataBuffer!
      );
      log(
        "attestationObject > authData > extensionsDataBufferBase64",
        extensionsDataBufferBase64
      );

      const flagsJson = parsedAuthData.flags;
      log("attestationObject > authData > flagsJson", flagsJson);
      console.log(
        `+ The flags list: https://w3c.github.io/webauthn/#authdata-flags`
      );

      const flagsBufBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.flagsBuf
      );
      log("attestationObject > authData > flagsBase64", flagsBufBase64);

      const rpIdHashBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthData.rpIdHash
      );
      log("attestationObject > authData > rpIdHashBase64", rpIdHashBase64);

      const defaultRpIdHash = Helpers.isoBase64URL.fromBuffer(
        await Helpers.toHash(
          Helpers.isoUint8Array.fromUTF8String(defaultPasskey.rpId)
        )
      );
      log("rpIdHash equal?", rpIdHashBase64 === defaultRpIdHash);
      // ...
    }

    // Verify With Banana Server
    if (bananaDebug) {
      const REGISTRATION_LAMBDA_URL =
        "https://8zfpr8iyag.execute-api.us-east-1.amazonaws.com/extract_qvalues";

      const attestationObjectBuffer = Helpers.base64URLStringToBuffer(
        attestationObjectBase64
      );

      const idBuffer = Helpers.base64URLStringToBuffer(
        registrationResponseJSON.id
      );

      const bananaRegRresp = await Axios.default({
        url: REGISTRATION_LAMBDA_URL,
        method: "post",
        params: {
          aObject: JSON.stringify(
            Array.from(new Uint8Array(attestationObjectBuffer))
          ),

          rawId: JSON.stringify(
            //@ts-ignore
            Array.from(new Uint8Array(idBuffer))
          ),
        },
      });

      const bananaRegMessage = bananaRegRresp.data.message;
      log("bananaRegMessage", bananaRegMessage);

      log(
        "credentialID equal?",
        registrationResponseJSON.id === (bananaRegMessage.encodedId as string)
      );
      log(
        "credentialPublicKeyXHex equal?",
        credentialPublicKeyXHex === (bananaRegMessage.q1hexString as string)
      );
      log(
        "credentialPublicKeyYHex equal?",
        credentialPublicKeyYHex === (bananaRegMessage.q2hexString as string)
      );
    }

    // ...
  }, handleCreatePasskeyDepList);

  // ---------------------------
  // --- Get Passkey Handler ---
  // ---------------------------

  const handleGetPasskeyDepList: React.DependencyList = [challengeGet];

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-authentication
  const handleGetPasskey = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeGet;

    const authenticationResponseJSON: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        challenge: challengeBase64,
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    // 取得 credentialIdHex
    const idHex = Helpers.base64URLStringToHex(authenticationResponseJSON.id);

    const authenticatorDataBase64 =
      authenticationResponseJSON.response.authenticatorData;

    const clientDataJSONBase64 =
      authenticationResponseJSON.response.clientDataJSON;

    const clientDataJSONUtf8 =
      Helpers.isoBase64URL.toString(clientDataJSONBase64);

    // Parse clientDataJSON
    const parsedClientDataJSONUtf8 =
      Helpers.splitClientDataJSONUtf8(clientDataJSONUtf8);

    const clientDataJSONPreUtf8 = parsedClientDataJSONUtf8.clientDataJSONPre;

    const clientDataJSONPostUtf8 = parsedClientDataJSONUtf8.clientDataJSONPost;

    const signatureBase64 = authenticationResponseJSON.response.signature;

    // Parse signature
    const parsedSignature = Helpers.parseEC2Signature(
      Helpers.isoBase64URL.toBuffer(signatureBase64)
    );

    const signatureRHex = `0x${Helpers.isoUint8Array.toHex(parsedSignature.r)}`;

    const signatureSHex = `0x${Helpers.isoUint8Array.toHex(parsedSignature.s)}`;

    const userHandleUtf8 = authenticationResponseJSON.response.userHandle!;

    if (debug) {
      console.warn(`+++ Get Passkey +++`);
      //   log("Authentication Response JSON", authenticationResponseJSON);
      log("* idBase64", authenticationResponseJSON.id);
      log("idHex", idHex);
      log("rawIdBase64", authenticationResponseJSON.rawId);
      log(
        "authenticationResponseJSON > authenticatorDataBase64",
        authenticatorDataBase64
      );

      // Parse authenticatorData
      const parsedAuthenticatorData = Helpers.parseAuthenticatorData(
        Helpers.isoBase64URL.toBuffer(authenticatorDataBase64)
      );

      const rpIdHashBase64 = Helpers.isoBase64URL.fromBuffer(
        parsedAuthenticatorData.rpIdHash
      );
      log(
        "authenticationResponseJSON > authenticatorData > rpIdHash",
        rpIdHashBase64
      );

      const flagsBuf = Helpers.isoBase64URL.fromBuffer(
        parsedAuthenticatorData.flagsBuf
      );
      log(
        "authenticationResponseJSON > authenticatorData > flagsBuf",
        flagsBuf
      );

      const flags = parsedAuthenticatorData.flags;
      log("authenticationResponseJSON > authenticatorData > flags", flags);

      const counter = parsedAuthenticatorData.counter;
      log("authenticationResponseJSON > authenticatorData > counter", counter);

      const counterBuf = Helpers.isoBase64URL.fromBuffer(
        parsedAuthenticatorData.counterBuf
      );
      log(
        "authenticationResponseJSON > authenticatorData > counterBuf",
        counterBuf
      );

      log(
        "authenticationResponseJSON > clientDataJSONBase64",
        clientDataJSONBase64
      );

      log(
        "* authenticationResponseJSON > clientDataJSON > preUtf8",
        clientDataJSONPreUtf8
      );
      log(
        "authenticationResponseJSON > clientDataJSON > challenge",
        parsedClientDataJSONUtf8.clientDataJSONChallenge
      );
      log(
        "* authenticationResponseJSON > clientDataJSON > postUtf8",
        clientDataJSONPostUtf8
      );

      log("authenticationResponseJSON > signatureBase64", signatureBase64);

      log("authenticationResponseJSON > signature > rHex", signatureRHex);
      log("authenticationResponseJSON > signature > sHex", signatureSHex);

      log("authenticationResponseJSON > userHandleBase64", userHandleUtf8);
    }

    // Verify With Banana Server
    if (bananaDebug) {
      const VERIFICATION_LAMBDA_URL =
        "https://muw05wa93c.execute-api.us-east-1.amazonaws.com/";

      let signatureValid = false;
      let bananaVerRresp;
      while (!signatureValid) {
        bananaVerRresp = await Axios.default({
          url: VERIFICATION_LAMBDA_URL,
          method: "post",
          params: {
            authDataRaw: JSON.stringify(
              Array.from(Helpers.isoBase64URL.toBuffer(authenticatorDataBase64))
            ),
            cData: JSON.stringify(
              Array.from(Helpers.isoBase64URL.toBuffer(clientDataJSONBase64))
            ),
            signature: JSON.stringify(
              Array.from(Helpers.isoBase64URL.toBuffer(signatureBase64))
            ),
          },
        });

        if (bananaVerRresp.data.message.processStatus === "success") {
          signatureValid = true;
        }
      }
      const bananaVerMessage = bananaVerRresp!.data.message;
      log("bananaVerMessage", bananaVerMessage);
    }

    // ...
  }, handleGetPasskeyDepList);

  // ---------------------
  // --- Input Handler ---
  // ---------------------

  const handleInputChangeDepList: React.DependencyList = [
    user,
    challengeCreate,
    authAttachChecked,
    authAttach,
  ];

  const handleInputChange = React.useCallback(
    (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
      // 更新 Input value
      const { id, value } = event.target;
      switch (id) {
        case InputId[InputId.userName]:
          setUser(value);
          break;
        case InputId[InputId.challengeCreate]:
          setChallengeCreate(value);
          break;
        case InputId[InputId.challengeGet]:
          setChallengeGet(value);
          break;
        case InputId[InputId.authenticatorAttachment]:
          if (value === "cross-platform") {
            setAuthAttachChecked(true);
            setAuthAttach("platform");
          }
          if (value === "platform") {
            setAuthAttachChecked(false);
            setAuthAttach("cross-platform");
          }
          break;
        default:
          break;
      }
      console.log(`Input: ${id} = ${value}`);
    },
    handleInputChangeDepList
  );

  return (
    <>
      <div className="w-5/6 m-auto p-3 border-2 border-purple-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">1. WebAuthN Local</h1>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            User Name
          </span>
          <input
            type="text"
            id={`${InputId[InputId.userName]}`}
            value={`${user}`}
            onChange={handleInputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Challenge Create
          </span>
          <input
            type="text"
            id={`${InputId[InputId.challengeCreate]}`}
            value={`${challengeCreate}`}
            onChange={handleInputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Challenge Get
          </span>
          <input
            type="text"
            id={`${InputId[InputId.challengeGet]}`}
            value={`${challengeGet}`}
            onChange={handleInputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Authenticator Attachment
          </span>
          <input
            type="checkbox"
            id={`${InputId[InputId.authenticatorAttachment]}`}
            value={`${authAttach}`}
            checked={authAttachChecked}
            onChange={handleInputChange}
            className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
          <label className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`Now is ${authAttach}`}</label>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <button
            onClick={handleCreatePasskey}
            className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base"
          >
            Create Passkey
          </button>
          <button
            onClick={handleGetPasskey}
            className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base"
          >
            Get Passkey
          </button>
        </div>
      </div>
    </>
  );
};
