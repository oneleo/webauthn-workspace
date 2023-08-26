// 目標：
// 1、Notification
// 提醒關係人，如：「CEO 您好，請確認簽名：冷錢包轉帳 100,000 USDT 至熱錢包，目前已完成 1/5 人簽名，尚差 2 人達執行門檻，確認交易後，請使用手機押指紋（Passkey）送簽」
// 2、Recovery
// 可用 zkProof 來證明帳戶可被還原，但 zkProof 證明是用 Google 認證過的 Gmail 來產生（或是 Passkey），再拿到鏈上證明將 Account 存取權要回來

import * as React from "react";
import * as Ethers from "ethers";
import * as Helpers from "./helpers/helpers";

import Axios from "axios";

import * as WebauthnBrowser from "@simplewebauthn/browser";
import * as WebauthnServer from "@simplewebauthn/server";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

// 此套件沒有更進一步解析 authData
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticators.ts#L33-L41
import * as WebauthnPass from "@passwordless-id/webauthn";

const url = "http://localhost:5173";

// 是否要求查看安全金鑰的製造商和型號
const attestationConveyancePreference: WebauthnTypes.AttestationConveyancePreference =
  "none"; // 選項："direct" | "enterprise" | "indirect" | "none"

// 逾時
const timeout = 300000; // 5 minutes

// Relying Party
const rpName = "imToken AA Server";
const rpId = "localhost";

// This Relying Party will accept either an ES256 or RS256 credential, but prefers an ES256 credential.
const pubKeyCredAlgEs256: WebauthnTypes.COSEAlgorithmIdentifier = -7;
const pubKeyCredAlgRs256: WebauthnTypes.COSEAlgorithmIdentifier = -257;

// Try to use UV if possible. This is also the default.
const pubKeyCredType: WebauthnTypes.PublicKeyCredentialType = "public-key";

// Make excludeCredentials check backwards compatible with credentials registered with U2F
const extensions = { poweredBy: "imToken Labs" };
// const extensions = { poweredBy: "imToken Labs", mnemonic: Mnemonic.mnemonic };

// 註 1：若使用虛擬驗證程式環境設定（Virtual Authenticator Environment）則必定是 cross-platform 驗證器
// 註 2：若要透過 platform 驗證器註冊／登入，請關閉虛擬驗證程式環境設定（屬於 cross-platform），否則會卡住（若執行第 2 次註冊／登入，Relying Part 會被懷疑要來識別用戶）
// https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client
const authenticatorAttachment: WebauthnTypes.AuthenticatorAttachment =
  "cross-platform"; // 選項："cross-platform" | "platform"
// 參數 requireResidentKey 及 residentKeyRequirement 會要求驗證器是否支援可發現憑證（Supports resident keys = passkey）
const requireResidentKey = true;
const residentKeyRequirement: ResidentKeyRequirement = "required"; // 選項："discouraged" | "preferred" | "required"
// 參數 userVerificationRequirement 會要求驗證器是否支援用戶驗證（Supports user verification）
const requireUserVerification = true;
const userVerificationRequirement: WebauthnTypes.UserVerificationRequirement =
  "required"; // 選項："discouraged" | "preferred" | "required"

// Don’t re-register any authenticator that has one of these credentials
const excludeCredentials: WebauthnTypes.PublicKeyCredentialDescriptorJSON[] = [
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
];

export const WebauthnApp = () => {
  const [user, setUser] = React.useState<string>("user");
  const [encodedId, setEncodedId] = React.useState<string>("");
  const [message, setMessage] = React.useState<string>("");

  // --------------------
  // -- Create Passkey --
  // --------------------

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-registration
  const handleCreatePasskey = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challenge = WebauthnPass.utils.randomChallenge();

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
    const userName = `${name}-${id}@${rpId}`;

    const regResp: WebauthnTypes.RegistrationResponseJSON =
      await WebauthnBrowser.startRegistration({
        rp: {
          name: rpName,
          id: rpId,
        },
        user: {
          id: userId,
          name: userName,
          displayName: userDisplayName,
        },
        challenge: challenge,
        pubKeyCredParams: [
          { alg: pubKeyCredAlgEs256, type: pubKeyCredType },
          { alg: pubKeyCredAlgRs256, type: pubKeyCredType },
        ],
        timeout: timeout,
        excludeCredentials: excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: authenticatorAttachment,
          requireResidentKey: requireResidentKey,
          residentKey: residentKeyRequirement,
          userVerification: userVerificationRequirement,
        },
        attestation: attestationConveyancePreference,
        extensions: extensions,
      } as WebauthnTypes.PublicKeyCredentialCreationOptionsJSON);

    console.log(`Registration Response: ${JSON.stringify(regResp, null, 2)}`);

    // ------------------------------
    // -- Parse Authenticator Data --
    // ------------------------------

    const attestationObject = regResp.response.attestationObject;
    console.log(`attestationObject: ${JSON.stringify(attestationObject)}`);

    const attestationObjectArray =
      Helpers.IsoBase64URL.toBuffer(attestationObject);

    const decodedAttestationObject = Helpers.decodeAttestationObject(
      attestationObjectArray
    );

    const authData = decodedAttestationObject.get("authData");

    const parsedAuthData = Helpers.parseAuthenticatorData(authData);
    console.log(
      `Parsed Authenticator Data: ${JSON.stringify(parsedAuthData, null, 2)}`
    );

    const rpIdHash = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.rpIdHash);
    console.log(`RP ID Hash: ${rpIdHash}`);

    const flagsBuf = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.flagsBuf);
    console.log(`Flags Buf: ${flagsBuf}`);

    const counterBuf = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.counterBuf
    );
    console.log(`Counter Buf: ${counterBuf}`);

    const aaguid = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.aaguid!);
    console.log(`AAGUID: ${aaguid}`);

    const credentialID = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialID!
    );
    console.log(`Credential ID: ${credentialID}`);

    const credentialPublicKey = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKey!
    );
    console.log(`Credential Public Key: ${credentialPublicKey}`);

    const credentialPublicKeyKty = parsedAuthData.credentialPublicKeyKty;
    console.log(`Credential Public Key Kty: ${credentialPublicKeyKty}`);

    const credentialPublicKeyAlg = parsedAuthData.credentialPublicKeyAlg;
    console.log(`Credential Public Key Alg: ${credentialPublicKeyAlg}`);

    const credentialPublicKeyCrv = parsedAuthData.credentialPublicKeyCrv;
    console.log(`Credential Public Key Crv: ${credentialPublicKeyCrv}`);

    const credentialPublicKeyX = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );
    const credentialPublicKeyXHex = `0x${Helpers.IsoUint8Array.toHex(
      parsedAuthData.credentialPublicKeyX!
    )}`;
    console.log(
      `Credential Public Key X:\n${credentialPublicKeyX}\n${credentialPublicKeyXHex}`
    );

    const credentialPublicKeyY = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );
    const credentialPublicKeyYHex = `0x${Helpers.IsoUint8Array.toHex(
      parsedAuthData.credentialPublicKeyY!
    )}`;
    console.log(
      `Credential Public Key Y:\n${credentialPublicKeyY}\n${credentialPublicKeyYHex}`
    );

    // --------------------------
    // -- Banana Wallet Server --
    // 1. response.data.message.encodedId = regResp.id = regResp.rawId = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.credentialID!)
    // 2. response.data.message.q0hexString = `0x${Helpers.IsoUint8Array.toHex(parsedAuthData.credentialPublicKeyX!)}`
    // 3. response.data.message.q1hexString = `0x${Helpers.IsoUint8Array.toHex(parsedAuthData.credentialPublicKeyY!)}`
    // --------------------------

    const REGISTRATION_LAMBDA_URL =
      "https://8zfpr8iyag.execute-api.us-east-1.amazonaws.com/extract_qvalues";

    const attestationObjectBuffer =
      Helpers.base64URLStringToBuffer(attestationObject);

    const rawIdBuffer = Helpers.base64URLStringToBuffer(regResp.rawId);

    // const response = await Axios({
    //   url: REGISTRATION_LAMBDA_URL,
    //   method: "post",
    //   params: {
    //     aObject: JSON.stringify(
    //       Array.from(new Uint8Array(attestationObjectBuffer))
    //     ),

    //     rawId: JSON.stringify(
    //       //@ts-ignore
    //       Array.from(new Uint8Array(rawIdBuffer))
    //     ),
    //   },
    // });

    // console.log(`Banana response: ${response}`);
    // console.log(`Banana response: ${JSON.stringify(response, null, 2)}`);

    // console.log(`Banana response data: ${response.data}`);
    // console.log(
    //   `Banana response data: ${JSON.stringify(response.data, null, 2)}`
    // );

    // console.log(`Banana response data message: ${response.data.message}`);
    // console.log(
    //   `Banana response data message: ${JSON.stringify(
    //     response.data.message,
    //     null,
    //     2
    //   )}`
    // );

    // console.log(
    //   `Banana response data message q0hexString: ${response.data.message.q0hexString}`
    // );
    // console.log(
    //   `Banana response data message q0hexString: ${JSON.stringify(
    //     response.data.message.q0hexString,
    //     null,
    //     2
    //   )}`
    // );

    // console.log(
    //   `Banana response data message q1hexString: ${response.data.message.q1hexString}`
    // );
    // console.log(
    //   `Banana response data message q1hexString: ${JSON.stringify(
    //     response.data.message.q1hexString,
    //     null,
    //     2
    //   )}`
    // );

    // console.log(
    //   `Banana response data message encodedId: ${response.data.message.encodedId}`
    // );
    // console.log(
    //   `Banana response data message encodedId: ${JSON.stringify(
    //     response.data.message.encodedId,
    //     null,
    //     2
    //   )}`
    // );

    // ...
  }, [user]);

  // -----------------
  // -- Get Passkey --
  // -----------------

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-authentication
  const handleGetPasskey = async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challenge = WebauthnPass.utils.randomChallenge();

    const authResp: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        challenge: challenge,
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    console.log(
      `Authentication Response: ${JSON.stringify(authResp, null, 2)}`
    );

    const authenticatorData = authResp.response.authenticatorData;
    console.log(`Authenticator Data: ${authenticatorData}`);

    const authDataBuffer = Helpers.IsoBase64URL.toBuffer(authenticatorData);

    const parsedAuthData = Helpers.parseAuthenticatorData(authDataBuffer);
    console.log(
      `Parsed Authenticator Data: ${JSON.stringify(parsedAuthData, null, 2)}`
    );

    const rpIdHash = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.rpIdHash);
    console.log(`RP ID Hash: ${rpIdHash}`);

    const flagsBuf = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.flagsBuf);
    console.log(`Flags Buf: ${flagsBuf}`);

    const counterBuf = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.counterBuf
    );
    console.log(`Counter Buf: ${counterBuf}`);

    const aaguid = Helpers.IsoBase64URL.fromBuffer(parsedAuthData.aaguid!);
    console.log(`AAGUID: ${aaguid}`);

    const credentialID = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialID!
    );
    console.log(`Credential ID: ${credentialID}`);

    const credentialPublicKey = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKey!
    );
    console.log(`Credential Public Key: ${credentialPublicKey}`);

    const credentialPublicKeyKty = parsedAuthData.credentialPublicKeyKty;
    console.log(`Credential Public Key Kty: ${credentialPublicKeyKty}`);

    const credentialPublicKeyAlg = parsedAuthData.credentialPublicKeyAlg;
    console.log(`Credential Public Key Alg: ${credentialPublicKeyAlg}`);

    const credentialPublicKeyCrv = parsedAuthData.credentialPublicKeyCrv;
    console.log(`Credential Public Key Crv: ${credentialPublicKeyCrv}`);

    const credentialPublicKeyX = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );
    console.log(`Credential Public Key X: ${credentialPublicKeyX}`);

    const credentialPublicKeyY = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );
    console.log(`Credential Public Key Y: ${credentialPublicKeyY}`);

    // ...
  };

  const handleSignMessage = React.useCallback(async () => {}, []);

  enum InputId {
    userName,
    message,
  }

  const handleInputChange = (
    event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    // 更新 React Hook
    const { id, value } = event.target;
    switch (id) {
      case InputId[InputId.userName]:
        setUser(value);
        break;
      case InputId[InputId.message]:
        setMessage(value);
        break;
      default:
        break;
    }
    console.log(`Input: ${id} = ${value}`);
  };

  const handleCoordinateHex = async () => {
    // From Simple WebAuthN
    const coordinateX = "CauffutyexEjW87UlFD-Q1ClONU8PHRBoU3MapT1TxE";
    const coordinateY = "Xh9vHH63OP11kaZrZHjZmXDiEsAZ8JANP_jLYCCwgm4";

    console.log(`coordinateX: ${coordinateX}`);
    console.log(`coordinateY: ${coordinateY}`);

    const coordinateXArray = Helpers.IsoBase64URL.toBuffer(coordinateX);
    const coordinateYArray = Helpers.IsoBase64URL.toBuffer(coordinateY);

    const coordinateXHex = `0x${Helpers.IsoUint8Array.toHex(coordinateXArray)}`;
    const coordinateYHex = `0x${Helpers.IsoUint8Array.toHex(coordinateYArray)}`;

    console.log(`coordinateXHex: ${coordinateXHex}`);
    console.log(`coordinateYHex: ${coordinateYHex}`);

    // From Banana Server
    const encodedId = "z8V8lGBTAru0o5yfA_XzS8p8ofuNMJAfjc52z6-ZFGQ";
    const q0hexString =
      "0x09ab9f7eeb727b11235bced49450fe4350a538d53c3c7441a14dcc6a94f54f11";
    const q1hexString =
      "0x5e1f6f1c7eb738fd7591a66b6478d99970e212c019f0900d3ff8cb6020b0826e";

    console.log(
      `${coordinateXHex === q0hexString} & ${coordinateYHex === q1hexString}`
    );

    // ...
  };

  return (
    <>
      <div>
        <span>Vite Env Test: {`${import.meta.env.VITE_PROVIDER}`}</span>
      </div>
      <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
        <input
          type="text"
          id={`${InputId[InputId.userName]}`}
          value={`${user}`}
          onChange={handleInputChange}
          className="order-1 w-2/4 m-auto p-3 border-0 rounded-lg text-base"
        ></input>
        <button
          onClick={handleCreatePasskey}
          className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
        >
          Create Passkey
        </button>
        <button
          onClick={handleGetPasskey}
          className="order-3 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
        >
          Validate Passkey
        </button>
      </div>
      <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
        <button
          onClick={handleCoordinateHex}
          className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
        >
          Coordinate to Address
        </button>
      </div>

      <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
        <input
          type="text"
          id={`${InputId[InputId.message]}`}
          value={`${message}`}
          onChange={handleInputChange}
          className="order-1 w-2/4 m-auto p-3 border-0 rounded-lg text-base"
        ></input>
        <button
          onClick={handleSignMessage}
          className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
        >
          Sign Message
        </button>
      </div>
    </>
  );
};
