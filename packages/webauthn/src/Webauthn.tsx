// 目標：
// 1、Notification
// 提醒關係人，如：「CEO 您好，請確認簽名：冷錢包轉帳 100,000 USDT 至熱錢包，目前已完成 1/5 人簽名，尚差 2 人達執行門檻，確認交易後，請使用手機押指紋（Passkey）送簽」
// 2、Recovery
// 可用 zkProof 來證明帳戶可被還原，但 zkProof 證明是用 Google 認證過的 Gmail 來產生（或是 Passkey），再拿到鏈上證明將 Account 存取權要回來

import * as React from "react";
import * as Ethers from "ethers";
import * as Helpers from "./helpers/helpers";

import { Banana, Chains } from "@rize-labs/banana-wallet-sdk";

import Axios from "axios";

import * as WebauthnBrowser from "@simplewebauthn/browser";
// import * as WebauthnServer from "@simplewebauthn/server";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

// 此套件沒有更進一步解析 authData
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticators.ts#L33-L41
// import * as WebauthnPass from "@passwordless-id/webauthn";

import * as typesVerifyPasskey from "../typechain-types/factories/contracts/VerifyPasskey__factory";

// -------------------------
// -- 設置基本 Passkey 參數 --
// -------------------------

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
    // const challenge = WebauthnPass.utils.randomChallenge();
    const challenge = Ethers.keccak256("0x1234").slice(2);

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
      Helpers.isoBase64URL.toBuffer(attestationObject);

    const decodedAttestationObject = Helpers.decodeAttestationObject(
      attestationObjectArray
    );

    const authData = decodedAttestationObject.get("authData");

    const parsedAuthData = Helpers.parseAuthenticatorData(authData);
    console.log(
      `Parsed Authenticator Data: ${JSON.stringify(parsedAuthData, null, 2)}`
    );

    const rpIdHash = Helpers.isoBase64URL.fromBuffer(parsedAuthData.rpIdHash);
    console.log(`RP ID Hash: ${rpIdHash}`);

    const rpIdHashHex = `0x${Helpers.isoUint8Array.toHex(
      parsedAuthData.rpIdHash
    )}`;
    console.log(`RP ID Hash Hex: ${rpIdHashHex}`);

    const flagsBuf = Helpers.isoBase64URL.fromBuffer(parsedAuthData.flagsBuf);
    console.log(`Flags Buf: ${flagsBuf}`);

    const counterBuf = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.counterBuf
    );
    console.log(`Counter Buf: ${counterBuf}`);

    const aaguid = Helpers.isoBase64URL.fromBuffer(parsedAuthData.aaguid!);
    console.log(`AAGUID: ${aaguid}`);

    const credentialID = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialID!
    );
    console.log(`Credential ID: ${credentialID}`);

    const credentialIDHex = `0x${Helpers.isoUint8Array.toHex(
      parsedAuthData.credentialID!
    )}`;
    console.log(`Credential ID Hex: ${credentialIDHex}`);

    const credentialPublicKey = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKey!
    );
    console.log(`Credential Public Key: ${credentialPublicKey}`);

    const credentialPublicKeyHex = `0x${Helpers.isoUint8Array.toHex(
      parsedAuthData.credentialPublicKey!
    )}`;
    console.log(`Credential Public Key Hex: ${credentialPublicKeyHex}`);

    const credentialPublicKeyKty = parsedAuthData.credentialPublicKeyKty;
    console.log(`Credential Public Key Kty: ${credentialPublicKeyKty}`);

    const credentialPublicKeyAlg = parsedAuthData.credentialPublicKeyAlg;
    console.log(`Credential Public Key Alg: ${credentialPublicKeyAlg}`);

    const credentialPublicKeyCrv = parsedAuthData.credentialPublicKeyCrv;
    console.log(`Credential Public Key Crv: ${credentialPublicKeyCrv}`);

    const credentialPublicKeyX = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );
    const credentialPublicKeyXHex = `0x${Helpers.isoUint8Array.toHex(
      parsedAuthData.credentialPublicKeyX!
    )}`;
    console.log(
      `Credential Public Key X:\n${credentialPublicKeyX}\n${credentialPublicKeyXHex}`
    );

    const credentialPublicKeyY = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );
    const credentialPublicKeyYHex = `0x${Helpers.isoUint8Array.toHex(
      parsedAuthData.credentialPublicKeyY!
    )}`;
    console.log(
      `Credential Public Key Y:\n${credentialPublicKeyY}\n${credentialPublicKeyYHex}`
    );

    // --------------------------
    // -- Banana Wallet Server --
    // 1. response.data.message.encodedId = regResp.id = regResp.rawId = Helpers.isoBase64URL.fromBuffer(parsedAuthData.credentialID!)
    // 2. response.data.message.q0hexString = `0x${Helpers.isoUint8Array.toHex(parsedAuthData.credentialPublicKeyX!)}`
    // 3. response.data.message.q1hexString = `0x${Helpers.isoUint8Array.toHex(parsedAuthData.credentialPublicKeyY!)}`
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
    console.log(`hostname: ${window.location.hostname}`); // localhost

    // ...
  }, [user]);

  // -----------------
  // -- Get Passkey --
  // -----------------

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-authentication
  const handleGetPasskey = async () => {
    // The challenge is produced by the server; see the Security Considerations
    // const challenge = WebauthnPass.utils.randomChallenge();
    const challenge = Ethers.keccak256("0x5678").slice(2);

    const authResp: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        challenge: challenge,
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    console.log(
      `Authentication Response: ${JSON.stringify(authResp, null, 2)}`
    );

    const authenticatorData = authResp.response.authenticatorData;
    console.log(`Authenticator Data: ${authenticatorData}`);

    const authDataBuffer = Helpers.isoBase64URL.toBuffer(authenticatorData);

    const parsedAuthData = Helpers.parseAuthenticatorData(authDataBuffer);
    console.log(
      `Parsed Authenticator Data: ${JSON.stringify(parsedAuthData, null, 2)}`
    );

    const rpIdHash = Helpers.isoBase64URL.fromBuffer(parsedAuthData.rpIdHash);
    console.log(`RP ID Hash: ${rpIdHash}`);

    const flagsBuf = Helpers.isoBase64URL.fromBuffer(parsedAuthData.flagsBuf);
    console.log(`Flags Buf: ${flagsBuf}`);

    const counterBuf = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.counterBuf
    );
    console.log(`Counter Buf: ${counterBuf}`);

    const aaguid = Helpers.isoBase64URL.fromBuffer(parsedAuthData.aaguid!);
    console.log(`AAGUID: ${aaguid}`);

    const credentialID = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialID!
    );
    console.log(`Credential ID: ${credentialID}`);

    const credentialPublicKey = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKey!
    );
    console.log(`Credential Public Key: ${credentialPublicKey}`);

    const credentialPublicKeyKty = parsedAuthData.credentialPublicKeyKty;
    console.log(`Credential Public Key Kty: ${credentialPublicKeyKty}`);

    const credentialPublicKeyAlg = parsedAuthData.credentialPublicKeyAlg;
    console.log(`Credential Public Key Alg: ${credentialPublicKeyAlg}`);

    const credentialPublicKeyCrv = parsedAuthData.credentialPublicKeyCrv;
    console.log(`Credential Public Key Crv: ${credentialPublicKeyCrv}`);

    const credentialPublicKeyX = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyX!
    );
    console.log(`Credential Public Key X: ${credentialPublicKeyX}`);

    const credentialPublicKeyY = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );
    console.log(`Credential Public Key Y: ${credentialPublicKeyY}`);

    // const res = await WebauthnServer.verifyAuthenticationResponse({
    //   response: authResp,
    //   expectedChallenge: challenge,
    //   expectedOrigin: "http://localhost:5173",
    //   expectedRPID: rpId,
    //   authenticator: {
    //     credentialPublicKey: parsedAuthData.credentialPublicKey!,
    //     credentialID: parsedAuthData.credentialID!,
    //     counter: parsedAuthData.counter,
    //   },
    // });
    // console.log(`res: ${JSON.stringify(res, null, 2)}`);
    // ...
  };

  // -----------------------------
  // -- Sign Message by Passkey --
  // -----------------------------

  // clientDataJSON
  // https://sepolia.etherscan.io/address/0xebacafdaa7d58831ddb20038e417bcc66f8a1378#readContract

  // clientDataJSONPre clientDataJSONPost
  // https://sepolia.etherscan.io/address/0xfdb5d960982190f0c26ad58267aa76ada6dad5e2#readContract

  const handleSignMessage = React.useCallback(async () => {
    // const challenge = message;
    const challenge = Ethers.keccak256("0x1234").slice(2);
    const testCredentialId = "ZToBeLvpI3DnfdP-PocXqMIhCX-J2JxYiY0_MeVTpwY";

    log("challenge", challenge);

    const pubKeyXBase64 = "p48OV1XXoNIJj6FmDT6W9D2i6o-whfiXu2XseKmlT8Y";
    const pubKeyYBase64 = "ANtrAXJ3uU7kLXDUmQMtOA3mfLdK7hfas4QIUmojVr4";

    const pubKeyXHex =
      "0xa78f0e5755d7a0d2098fa1660d3e96f43da2ea8fb085f897bb65ec78a9a54fc6";
    const pubKeyYHex =
      "0x00db6b017277b94ee42d70d499032d380de67cb74aee17dab38408526a2356be";

    const authResp: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        allowCredentials: [
          { id: testCredentialId, type: "public-key" },
        ] as WebauthnTypes.PublicKeyCredentialDescriptorJSON[],
        userVerification:
          "required" as WebauthnTypes.UserVerificationRequirement,
        challenge: challenge,
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    // authenticatorData
    const authenticatorData = authResp.response.authenticatorData;
    log("authenticatorDataBase64", authenticatorData);

    const authenticatorDataRaw =
      Helpers.isoBase64URL.toString(authenticatorData);
    log("authenticatorDataRaw", authenticatorDataRaw);

    const authenticatorDataHex =
      Helpers.base64URLStringToHex(authenticatorData);
    log("authenticatorDataHex", authenticatorDataHex);

    // clientDataJSON
    const clientDataJSON = authResp.response.clientDataJSON;
    log("clientDataJSONBase64", clientDataJSON);

    const clientDataJSONRaw = Helpers.isoBase64URL.toString(clientDataJSON);
    log("clientDataJSONRaw", clientDataJSONRaw);

    const clientDataJSONHex = Helpers.base64URLStringToHex(clientDataJSON);
    log("clientDataJSONHex", clientDataJSONHex);

    // signature
    const signature = authResp.response.signature;

    const signatureRaw = Helpers.isoBase64URL.toString(signature);
    log("signatureRaw", signatureRaw);

    const signatureHex = Helpers.base64URLStringToHex(signature);
    log("signatureHex", signatureHex);

    // Parse authenticatorData
    const parsedAuthData = Helpers.parseAuthenticatorData(
      Helpers.isoBase64URL.toBuffer(authenticatorData)
    );
    // log("parsedAuthData", parsedAuthData);
    // parsedAuthData.credentialPublicKeyX = undefined
    // parsedAuthData.credentialPublicKeyY = undefined

    // parse clientDataJSON
    const parsedClientDataJSON = Helpers.splitClientDataJSONWithByte32Challenge(
      clientDataJSONRaw,
      "http://localhost:5173"
    );
    // log("parsedClientDataJSON", parsedClientDataJSON);

    log("clientDataJSONPreRaw", parsedClientDataJSON.clientDataJSONPre);
    log("challengeRaw", parsedClientDataJSON.clientDataJSONChallenge);
    log("clientDataJSONPostRaw", parsedClientDataJSON.clientDataJSONPost);

    const clientDataJSONPreBase64 = Helpers.isoBase64URL.fromString(
      parsedClientDataJSON.clientDataJSONPre
    );
    const clientDataJSONChallengeBase64 = Helpers.isoBase64URL.fromString(
      parsedClientDataJSON.clientDataJSONChallenge
    );
    const clientDataJSONPostBase64 = Helpers.isoBase64URL.fromString(
      parsedClientDataJSON.clientDataJSONPost
    );

    log("clientDataJSONPreBase64", clientDataJSONPreBase64);
    log("clientDataJSONChallenge", clientDataJSONChallengeBase64);
    log("clientDataJSONPostBase64", clientDataJSONPostBase64);

    const clientDataJSONPreHex = Helpers.utf8StringToHex(
      parsedClientDataJSON.clientDataJSONPre
    );
    const clientDataJSONChallengeHex = Helpers.utf8StringToHex(
      parsedClientDataJSON.clientDataJSONChallenge
    );
    const clientDataJSONPostHex = Helpers.utf8StringToHex(
      parsedClientDataJSON.clientDataJSONPost
    );

    log("clientDataJSONPreHex", clientDataJSONPreHex);
    log("clientDataJSONChallengeHex", clientDataJSONChallengeHex);
    log("clientDataJSONPostHex", clientDataJSONPostHex);

    // Parse signature
    const parsedSignature = Helpers.parseEC2Signature(
      Helpers.isoBase64URL.toBuffer(signature)
    );
    // log("parsedSignature", parsedSignature);

    const parsedSignatureRHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignature.r
    )}`;
    log("parsedSignatureRHex", parsedSignatureRHex);

    const parsedSignatureSHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignature.s
    )}`;
    log(`parsedSignatureSHex`, parsedSignatureSHex);

    log(`pubKeyX`, pubKeyXHex);
    log(`pubKeyY`, pubKeyYHex);

    const concatXYRS =
      pubKeyXHex +
      pubKeyYHex.slice(2) +
      parsedSignatureRHex.slice(2) +
      parsedSignatureSHex.slice(2);

    const abi = Ethers.AbiCoder.defaultAbiCoder();

    const encodedXYRS = abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [pubKeyXHex, pubKeyYHex, parsedSignatureRHex, parsedSignatureSHex]
    );

    const decodedXYRS = abi.decode(
      ["uint256", "uint256", "uint256", "uint256"],
      encodedXYRS // = concatXYRS
    );

    const xUint256 = decodedXYRS[0];
    const yUint256 = decodedXYRS[1];
    const rUint256 = decodedXYRS[2];
    const sUint256 = decodedXYRS[3];
    console.log(
      `xUint256: ${xUint256}\nyUint256: ${yUint256}\nrUint256: ${rUint256}\nsUint256: ${sUint256}`
    );

    const clientDataJSONEncode = abi.encode(["string"], [clientDataJSON]);
    const authenticatorDataEncode = abi.encode(["string"], [authenticatorData]);

    log("clientDataJSONEncode", clientDataJSONEncode);
    log("authenticatorDataEncode", authenticatorDataEncode);

    const clientDataJSONEncode2 = Ethers.encodeBytes32String(clientDataJSON);
    const authenticatorDataEncode2 =
      Ethers.encodeBytes32String(authenticatorData);

    log("clientDataJSONEncode2", clientDataJSONEncode2);
    log("authenticatorDataEncode2", authenticatorDataEncode2);

    // --------------------------
    // -- Banana Wallet Server --
    // --------------------------
    const VERIFICATION_LAMBDA_URL =
      "https://muw05wa93c.execute-api.us-east-1.amazonaws.com/";

    // let signatureValid = false;
    // let signature;
    // while (!signatureValid) {
    //   signature = await Axios({
    //     url: VERIFICATION_LAMBDA_URL,
    //     method: "post",
    //     params: {
    //       authDataRaw: JSON.stringify(Array.from(authDataArray)),
    //       cData: JSON.stringify(Array.from(authClientDataArray)),
    //       signature: JSON.stringify(Array.from(authSigArray)),
    //     },
    //   });

    //   if (signature.data.message.processStatus === "success") {
    //     signatureValid = true;
    //   }
    // }

    // console.log(`Banana response: ${signature}`);
    // console.log(`Banana response: ${JSON.stringify(signature, null, 2)}`);

    // console.log(`Banana response data: ${signature!.data}`);
    // console.log(
    //   `Banana response data: ${JSON.stringify(signature!.data, null, 2)}`
    // );

    // console.log(`Banana response data message: ${signature!.data.message}`);
    // console.log(
    //   `Banana response data message: ${JSON.stringify(
    //     signature!.data.message,
    //     null,
    //     2
    //   )}`
    // );

    // console.log(
    //   `Banana response data message sig: ${
    //     signature!.data.message.finalSignature
    //   }`
    // );
    // console.log(
    //   `Banana response data message sig: ${JSON.stringify(
    //     signature!.data.message.finalSignature,
    //     null,
    //     2
    //   )}`
    // );

    // ================================

    // ================================
    // const value = authClientDataHex.slice(72, 248);
    // console.log(`value: ${value}`);
    // const clientDataJsonRequestId = Ethers.keccak256("0x" + value);
    // const finalSignatureWithMessage =
    //   authSigHex + clientDataJsonRequestId.slice(2);
    // console.log(`finalSignatureWithMessage: ${finalSignatureWithMessage}`);

    // const decoded = Ethers.AbiCoder.defaultAbiCoder().decode(
    //   ["uint256", "uint256", "uint256"],
    //   finalSignatureWithMessage
    // );

    // console.log(`decoded: ${decoded}`);

    // const signedMessage = decoded[2];
  }, [message]);

  // -----------------------------
  // -- Create and Sign Message by Passkey --
  // -----------------------------

  const handleCreateAndSignChallenge = async () => {
    // -------------------------------
    // -- create 註冊一組新的 Passkey --
    // -------------------------------

    // let challenge = userOpHash;
    const challengeCreate = Ethers.keccak256("0x1234");
    log("challengeCreate", challengeCreate);

    const challengeGet = Ethers.keccak256("0x5678");
    log("challengeGet", challengeGet);

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

    // create 註冊一組新的 Passkey
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
        challenge: challengeCreate.slice(2),
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

    // 解析 authData
    const attestationObject = regResp.response.attestationObject;

    const attestationObjectArray =
      Helpers.isoBase64URL.toBuffer(attestationObject);

    const decodedAttestationObject = Helpers.decodeAttestationObject(
      attestationObjectArray
    );

    const authData = decodedAttestationObject.get("authData");

    const parsedAuthData = Helpers.parseAuthenticatorData(authData);

    // 取得 credentialId
    // 註：credentialId 只能在 create 註冊階段才能取得，即使在 get 簽名階段也有 authData 變數（ = undefined）
    const credentialID = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialID!
    );

    // 取得 credentialPublicKeyX 與 credentialPublicKeyYHex
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyX = parsedAuthData.credentialPublicKeyX!;
    const credentialPublicKeyY = parsedAuthData.credentialPublicKeyY!;

    const credentialPublicKeyXHex = `0x${Helpers.isoUint8Array.toHex(
      credentialPublicKeyX
    )}`;
    const credentialPublicKeyYHex = `0x${Helpers.isoUint8Array.toHex(
      credentialPublicKeyY
    )}`;

    log("credentialID", credentialID);
    log("credentialPublicKeyXHex", credentialPublicKeyXHex);
    log("credentialPublicKeyYHex", credentialPublicKeyYHex);

    // -------------------------------
    // -- Verify With Banana Server --
    // -------------------------------

    // const REGISTRATION_LAMBDA_URL =
    //   "https://8zfpr8iyag.execute-api.us-east-1.amazonaws.com/extract_qvalues";

    // const attestationObjectBuffer =
    //   Helpers.base64URLStringToBuffer(attestationObject);

    // const rawIdBuffer = Helpers.base64URLStringToBuffer(regResp.rawId);

    // const bananaRegRresp = await Axios({
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

    // const bananaRegMessage = bananaRegRresp.data.message;
    // log("bananaRegMessage", bananaRegMessage);

    // log(
    //   "credentialID equal?",
    //   credentialID === (bananaRegMessage.encodedId as string)
    // );
    // log(
    //   "credentialPublicKeyXHex equal?",
    //   credentialPublicKeyXHex === (bananaRegMessage.q1hexString as string)
    // );
    // log(
    //   "credentialPublicKeyYHex equal?",
    //   credentialPublicKeyYHex === (bananaRegMessage.q2hexString as string)
    // );

    // --------------------------------------
    // -- get 使用 Passkey 對 challenge 簽名 --
    // --------------------------------------

    // 註：打 ☆ 者：表示確定有在 Demo 中出現：
    // https://mumbai.polygonscan.com/tx/0x701cf3790cce6ae20190be90518c8f8430a3c542a40993e84fe6b37d6d4837de

    const abi = Ethers.AbiCoder.defaultAbiCoder();

    // get 使用 Passkey 對 challenge 簽名
    const authResp: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        allowCredentials: [
          { id: credentialID, type: "public-key" },
        ] as WebauthnTypes.PublicKeyCredentialDescriptorJSON[],
        userVerification:
          "required" as WebauthnTypes.UserVerificationRequirement,
        challenge: challengeGet.slice(2),
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    // 取得 authenticatorData
    const authenticatorDataBase64 = authResp.response.authenticatorData;
    log("authenticatorDataBase64", authenticatorDataBase64);

    const authenticatorDataHex = Helpers.base64URLStringToHex(
      authenticatorDataBase64
    ); // ☆：會是「0500000000」結尾
    log("authenticatorDataHex", authenticatorDataHex);

    const authenticatorDataBase64Bytes = abi.encode(
      ["string"],
      [authenticatorDataBase64]
    );
    log("authenticatorDataBase64Bytes", authenticatorDataBase64Bytes);

    // 取得 clientDataJSONPre、clientDataJSONChallenge、clientDataJSONPost
    const clientDataJSONBase64 = authResp.response.clientDataJSON;

    const clientDataJSONBase64Bytes = abi.encode(
      ["string"],
      [clientDataJSONBase64]
    );

    const clientDataJSONUtf8 =
      Helpers.isoBase64URL.toString(clientDataJSONBase64);

    const clientDataJSONHex =
      Helpers.base64URLStringToHex(clientDataJSONBase64); // ☆：不含 Challenge

    log("clientDataJSONBase64", clientDataJSONBase64);
    log("clientDataJSONBase64Bytes", clientDataJSONBase64Bytes);
    log("clientDataJSONUtf8", clientDataJSONUtf8);
    log("clientDataJSONHex", clientDataJSONHex);

    const { clientDataJSONPre, clientDataJSONChallenge, clientDataJSONPost } =
      Helpers.splitClientDataJSONWithByte32Challenge(
        clientDataJSONUtf8,
        "http://localhost:5173"
      );

    log("clientDataJSONPreUtf8", clientDataJSONPre);
    log("clientDataJSONChallengeUtf8", clientDataJSONChallenge);
    log("clientDataJSONPostUtf8", clientDataJSONPost);

    const clientDataJSONPreBase64 =
      Helpers.isoBase64URL.fromString(clientDataJSONPre);

    const clientDataJSONChallengeBase64 = Helpers.isoBase64URL.fromString(
      clientDataJSONChallenge
    );

    const clientDataJSONPostBase64 =
      Helpers.isoBase64URL.fromString(clientDataJSONPost);

    log("clientDataJSONPreBase64", clientDataJSONPreBase64);
    log("clientDataJSONChallengeBase64", clientDataJSONChallengeBase64);
    log("clientDataJSONPostBase64", clientDataJSONPostBase64);

    const clientDataJSONPreHex = Helpers.base64URLStringToHex(
      clientDataJSONPreBase64
    ); // ☆：搜尋整個「7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22」

    const clientDataJSONChallengeHex = Helpers.base64URLStringToHex(
      clientDataJSONChallengeBase64
    );

    const clientDataJSONPostHex = Helpers.base64URLStringToHex(
      clientDataJSONPostBase64
    ); // ☆：搜尋前面「222c226f726967696e223a2268747470」部份

    log("clientDataJSONPreHex", clientDataJSONPreHex);
    log("clientDataJSONChallengeHex", clientDataJSONChallengeHex);
    log("clientDataJSONPostHex", clientDataJSONPostHex);

    // 取得 signatureR 與 signatureS
    const signatureBase64 = authResp.response.signature;

    const parsedSignature = Helpers.parseEC2Signature(
      Helpers.isoBase64URL.toBuffer(signatureBase64)
    );

    const parsedSignatureRHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignature.r
    )}`;

    const parsedSignatureSHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignature.s
    )}`;

    log("parsedSignatureRHex", parsedSignatureRHex);
    log("parsedSignatureSHex", parsedSignatureSHex);

    // 將 X、Y、R、S 轉換為 uint256
    const encodedXYRS = abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        credentialPublicKeyXHex,
        credentialPublicKeyYHex,
        parsedSignatureRHex,
        parsedSignatureSHex,
      ]
    );

    const [x, y, r, s] = abi.decode(
      ["uint256", "uint256", "uint256", "uint256"],
      encodedXYRS // = concatXYRS
    );

    console.log(`x: ${x}\ny: ${y}\nr: ${r}\ns: ${s}`);

    // -------------------------------
    // -- Verify With Banana Server --
    // -------------------------------

    // const VERIFICATION_LAMBDA_URL =
    //   "https://muw05wa93c.execute-api.us-east-1.amazonaws.com/";

    // let signatureValid = false;
    // let bananaVerRresp;
    // while (!signatureValid) {
    //   bananaVerRresp = await Axios({
    //     url: VERIFICATION_LAMBDA_URL,
    //     method: "post",
    //     params: {
    //       authDataRaw: JSON.stringify(
    //         Array.from(Helpers.isoBase64URL.toBuffer(authenticatorDataBase64))
    //       ),
    //       cData: JSON.stringify(
    //         Array.from(Helpers.isoBase64URL.toBuffer(clientDataJSONBase64))
    //       ),
    //       signature: JSON.stringify(
    //         Array.from(Helpers.isoBase64URL.toBuffer(signatureBase64))
    //       ),
    //     },
    //   });

    //   if (bananaVerRresp.data.message.processStatus === "success") {
    //     signatureValid = true;
    //   }
    // }

    // const bananaVerMessage = bananaVerRresp!.data.message;
    // log("bananaVerMessage", bananaVerMessage);

    // -----------------------------------
    // -- Verify Signature via Contract --
    // -----------------------------------

    const clientDataJSONPack = abi.encode(
      ["string", "string"],
      [clientDataJSONPre, clientDataJSONPost]
    );

    const verifyPasskeyAddress = "0xfc651ac35999E24F6eC50C915a29a81258781c4C";

    const provider = new Ethers.JsonRpcProvider(
      `${import.meta.env.VITE_PROVIDER}`
    );

    const verifyPasskeyContract =
      typesVerifyPasskey.VerifyPasskey__factory.connect(
        verifyPasskeyAddress,
        provider
      );

    let readTransaction = await verifyPasskeyContract.verifySignature(
      x,
      y,
      r,
      s,
      authenticatorDataHex, // ☆
      clientDataJSONPack, // ☆？
      challengeGet
    );
    log("readTransaction", readTransaction);

    // ...
  };

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

    const coordinateXArray = Helpers.isoBase64URL.toBuffer(coordinateX);
    const coordinateYArray = Helpers.isoBase64URL.toBuffer(coordinateY);

    const coordinateXHex = `0x${Helpers.isoUint8Array.toHex(coordinateXArray)}`;
    const coordinateYHex = `0x${Helpers.isoUint8Array.toHex(coordinateYArray)}`;

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
    // ++++++++++++++++++++

    const authSig =
      "MEYCIQD8xiv6YVIZ2TEgtW7Tgh1faF-R9B3ZdEtIvw9BmF7EZQIhAN6b1L_mqHKyVbaz9MY13NbIWdFlIX5HpQ-IQiFJG8L_";
    const bananaR =
      "0xfcc62bfa615219d93120b56ed3821d5f685f91f41dd9744b48bf0f41985ec465";
    const bananaS =
      "0xde9bd4bfe6a872b255b6b3f4c635dcd6c859d165217e47a50f884221491bc2ff";

    const authSigArray = Helpers.isoBase64URL.toBuffer(authSig);
    const parsedSignature = Helpers.parseEC2Signature(authSigArray);

    // const parsedSignatureR = Helpers.bufferToBase64URLString(parsedSignature.r);
    // const parsedSignatureRArray =
    //   Helpers.isoBase64URL.toBuffer(parsedSignatureR);
    const parsedSignatureRHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignature.r
    )}`;

    console.log(`parsedSignatureRHex: ${parsedSignatureRHex}`);

    const parsedSignatureS = Helpers.bufferToBase64URLString(parsedSignature.s);
    const parsedSignatureSArray =
      Helpers.isoBase64URL.toBuffer(parsedSignatureS);
    const parsedSignatureSHex = `0x${Helpers.isoUint8Array.toHex(
      parsedSignatureSArray
    )}`;

    console.log(`parsedSignatureSHex: ${parsedSignatureSHex}`);

    console.log(
      `${parsedSignatureRHex === bananaR} & ${parsedSignatureSHex === bananaS}`
    );

    // ++++++++++++++++++++

    const authenticatorData =
      "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQAAAAAAAAAAAAAAAAAAAAAAIGU6AXi76SNw533T_j6HF6jCIQl_idicWImNPzHlU6cGpQECAyYgASFYIKePDldV16DSCY-hZg0-lvQ9ouqPsIX4l7tl7HippU_GIlggANtrAXJ3uU7kLXDUmQMtOA3mfLdK7hfas4QIUmojVr4";
    const authenticatorDataHex =
      Helpers.base64URLStringToHex(authenticatorData);
    console.log(`authenticatorDataHex: ${authenticatorDataHex}`);

    const clientDataJSON_Reg =
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYTE1NGExMWItZTlkOS00Y2Y5LTk3ZDAtZmNjYTQzY2M0M2ZlIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ";
    const clientDataJSONHex_Reg =
      Helpers.base64URLStringToHex(clientDataJSON_Reg);
    console.log(`clientDataJSONHex_Reg: ${clientDataJSONHex_Reg}`);

    const clientDataJSON_Sig =
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMTIwIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ";
    const clientDataJSONHex_Sig =
      Helpers.base64URLStringToHex(clientDataJSON_Sig);
    const clientDataJSONUTF8Stinrg_Sig =
      Helpers.isoBase64URL.toString(clientDataJSON_Sig);

    // const clientDataJSONHex_Sig =
    //   "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22aaa6e9d1c0279ad908df20785773e1115966b5ffbc73be32aead206eb11324e0222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d";

    console.log(`clientDataJSONHex_Sig: ${clientDataJSONHex_Sig}`);
    console.log(
      `clientDataJSONUTF8Stinrg_Sig: ${clientDataJSONUTF8Stinrg_Sig}`
    );
    // 假設不含 0x 前綴
    // 0 ~ 71 = clientDataJSONPre
    // 72 ~ 135 = challenge base/hex? string
    // 136 ~ 248 = clientDataJsonPost
    console.log(
      `clientDataJSONHex_Sig.slice(72, 248): ${clientDataJSONHex_Sig.slice(
        136,
        248
      )}`
    );

    const clientDataJsonRequestId = Ethers.keccak256(
      `0x${clientDataJSONHex_Sig.slice(72, 248)}`
    );
    console.log(`clientDataJsonRequestId: ${clientDataJsonRequestId}`);

    const bananaFinalSignature =
      "0xfcc62bfa615219d93120b56ed3821d5f685f91f41dd9744b48bf0f41985ec465de9bd4bfe6a872b255b6b3f4c635dcd6c859d165217e47a50f884221491bc2ffaaa6e9d1c0279ad908df20785773e1115966b5ffbc73be32aead206eb11324e0";
    const finalSignatureWithMessage =
      bananaFinalSignature + clientDataJsonRequestId.slice(2);

    const abi = Ethers.AbiCoder.defaultAbiCoder();
    const decoded = abi.decode(
      ["uint256", "uint256", "uint256"],
      finalSignatureWithMessage
    );
    console.log(`decoded: ${decoded}`);
    console.log(`decoded[2]: ${decoded[2]}`);

    const testClientDataJSONUTF8String = `{"type":"webauthn.get","challenge":"${Ethers.encodeBytes32String(
      "xxxxxx"
    ).slice(2)}","origin":"http://localhost:5173","crossOrigin":false}`;
    const testSplit = Helpers.splitClientDataJSONWithByte32Challenge(
      testClientDataJSONUTF8String,
      "http://localhost:5173"
    );
    console.log(`testSplit: ${JSON.stringify(testSplit, null, 2)}`);

    console.log(`pre: ${Helpers.utf8StringToHex(testSplit.clientDataJSONPre)}`);
    console.log(
      `challenge: ${Helpers.utf8StringToHex(testSplit.clientDataJSONChallenge)}`
    );
    console.log(
      `challenge: ${Helpers.hexToUTF8String(
        Helpers.utf8StringToHex(testSplit.clientDataJSONChallenge)
      )}`
    );
    console.log(
      `post: ${Helpers.utf8StringToHex(testSplit.clientDataJSONPost)}`
    );

    console.log(
      Ethers.keccak256(
        "0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22313230222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d"
      )
    );

    console.log(
      Ethers.sha256(
        "0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22313230222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d"
      )
    );

    // ++++++++++
    log("test", Ethers.keccak256("0x1234").slice(2));

    // +++++++++++

    // -----------------------
    // -- Banana Wallet SDK --
    // -----------------------

    // const bananaInstance = new Banana(Chains.mumbai);
    // const walletName = "sample-wallet";
    // const walletInstance = await bananaInstance.connectWallet(walletName);
    // const sampleMsg = "Hello World";
    // const signer = walletInstance.getSigner();
    // const signMessageResponse = await signer.signBananaMessage(sampleMsg);
    // const signatureResp = signMessageResponse.signature;
    // log("signatureResp", signatureResp);

    const clientDataJSONPreBase64 =
      "dHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6Ig";
    const clientDataJSONPreHex = Helpers.base64URLStringToHex(
      clientDataJSONPreBase64
    );
    log("clientDataJSONPreHex", clientDataJSONPreHex);

    const clientDataJSONPreKeccak256 = Ethers.keccak256(clientDataJSONPreHex);
    log("clientDataJSONPreKeccak256", clientDataJSONPreKeccak256);

    const clientDataJSONPreSha256 = Ethers.sha256(clientDataJSONPreHex);
    log("clientDataJSONPreSha256", clientDataJSONPreSha256);

    const clientDataJSONPreBase64Bytes = abi.encode(
      ["string"],
      [clientDataJSONPreBase64]
    );
    const clientDataJSONPreBase64BytesKeccak256 = Ethers.keccak256(
      clientDataJSONPreBase64Bytes
    );
    log(
      "clientDataJSONPreBase64BytesKeccak256",
      clientDataJSONPreBase64BytesKeccak256
    );

    const clientDataJSONPreBase64BytesSha256 = Ethers.sha256(
      clientDataJSONPreBase64Bytes
    );
    log(
      "clientDataJSONPreBase64BytesSha256",
      clientDataJSONPreBase64BytesSha256
    );

    const challengeGet =
      "0x849e29e8884c27865098e077e0a171e11c6a5c6f45469334780d37e175b502a4";
    const challengeGetKeccak256 = Ethers.keccak256(challengeGet);
    log("challengeGetKeccak256", challengeGetKeccak256);

    const challengeGetSha256 = Ethers.sha256(challengeGet);
    log("challengeGetSha256", challengeGetSha256);

    const clientDataJSONBase64 =
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiODQ5ZTI5ZTg4ODRjMjc4NjUwOThlMDc3ZTBhMTcxZTExYzZhNWM2ZjQ1NDY5MzM0NzgwZDM3ZTE3NWI1MDJhNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0";

    const clientDataJSONBase64Bytes = abi.encode(
      ["string"],
      [clientDataJSONBase64]
    );
    const clientDataJSONBase64BytesKeccak256 = Ethers.keccak256(
      clientDataJSONBase64Bytes
    );
    log(
      "clientDataJSONBase64BytesKeccak256",
      clientDataJSONBase64BytesKeccak256
    );

    const clientDataJSONBase64BytesSha256 = Ethers.sha256(
      clientDataJSONBase64Bytes
    );
    log("clientDataJSONBase64BytesSha256", clientDataJSONBase64BytesSha256);

    const authenticatorDataBase64Bytes =
      "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000032535a594e3559674f6a4768304e4263505a485a6757345f6b72726d69686a4c486d567a7a756f4d646c324d464141414141670000000000000000000000000000";

    const authenticatorDataBase64 = abi.decode(
      ["string"],
      authenticatorDataBase64Bytes
    );
    log("authenticatorDataBase64", authenticatorDataBase64);

    const authenticatorDataBase64BytesKeccak256 = Ethers.keccak256(
      authenticatorDataBase64Bytes
    );
    log(
      "authenticatorDataBase64BytesKeccak256",
      authenticatorDataBase64BytesKeccak256
    );

    const authenticatorDataBase64BytesSha256 = Ethers.sha256(
      authenticatorDataBase64Bytes
    );
    log(
      "authenticatorDataBase64BytesSha256",
      authenticatorDataBase64BytesSha256
    );

    const credentialID = "CfOqmyI_NooPHPgTB6iNANjt-hGm5lTuFEpeHwkQLyk";

    const credentialIDBytes = abi.encode(["string"], [credentialID]);

    const credentialIDBytesKeccak256 = Ethers.keccak256(credentialIDBytes);
    log("credentialIDBytesKeccak256", credentialIDBytesKeccak256);

    const credentialIDBytesSha256 = Ethers.sha256(credentialIDBytes);
    log("credentialIDBytesSha256", credentialIDBytesSha256);

    const authDataBuffer = Helpers.isoBase64URL.toBuffer(
      "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg"
    );

    const clientDataHash = await Helpers.toHash(
      Helpers.isoBase64URL.toBuffer(
        "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiODQ5ZTI5ZTg4ODRjMjc4NjUwOThlMDc3ZTBhMTcxZTExYzZhNWM2ZjQ1NDY5MzM0NzgwZDM3ZTE3NWI1MDJhNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
      )
    );
    const clientDataHashHex = `0x${Helpers.isoUint8Array.toHex(
      clientDataHash
    )}`;
    log("clientDataHashHex", clientDataHashHex);
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
      <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
        <button
          onClick={handleCreateAndSignChallenge}
          className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
        >
          Create And Sign Challenge
        </button>
      </div>
    </>
  );
};

const log = (name: string, value: any) => {
  let jsonString: string;
  try {
    jsonString = JSON.stringify(value, null, 2);
  } catch (e) {
    console.log(`${name}: ${value.toString()}`);
    return;
  }
  console.log(`${name}: ${jsonString}`);
};
