// 目標：
// 1、Notification
// 提醒關係人，如：「CEO 您好，請確認簽名：冷錢包轉帳 100,000 USDT 至熱錢包，目前已完成 1/5 人簽名，尚差 2 人達執行門檻，確認交易後，請使用手機押指紋（Passkey）送簽」
// 2、Recovery
// 可用 zkProof 來證明帳戶可被還原，但 zkProof 證明是用 Google 認證過的 Gmail 來產生（或是 Passkey），再拿到鏈上證明將 Account 存取權要回來

import * as React from "react";
import * as Ethers from "ethers";
import * as Helpers from "./helpers/helpers";

import Axios from "axios";

import * as Mnemonic from "./mnemonic";

import * as WebauthnPass from "@passwordless-id/webauthn";
import * as WebauthnBrowser from "@simplewebauthn/browser";
import * as WebauthnServer from "@simplewebauthn/server";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

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

    const attestationObject = regResp.response.attestationObject;

    const decodedAttestationObject = Helpers.decodeAttestationObject(
      Helpers.IsoBase64URL.toBuffer(attestationObject)
    );

    const authData = decodedAttestationObject.get("authData");

    const parsedAuthData = Helpers.parseAuthenticatorData(authData);
    console.log(
      `Parsed Authenticator Data: ${JSON.stringify(parsedAuthData, null, 2)}`
    );

    console.log(`attestationObject: ${JSON.stringify(attestationObject)}`);

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

    const credentialPublicKeyX = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );
    console.log(`Credential Public Key X: ${credentialPublicKeyX}`);

    const credentialPublicKeyY = Helpers.IsoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );
    console.log(`Credential Public Key Y: ${credentialPublicKeyY}`);

    // ...
  }, [user]);

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

    // const clientDataJSON = decodeClientDataJSON(
    //   authResp.response.clientDataJSON
    // );

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
