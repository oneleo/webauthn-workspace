// 目標：
// 1、Notification
// 提醒關係人，如：「CEO 您好，請確認簽名：冷錢包轉帳 100,000 USDT 至熱錢包，目前已完成 1/5 人簽名，尚差 2 人達執行門檻，確認交易後，請使用手機押指紋（Passkey）送簽」
// 2、Recovery
// 可用 zkProof 來證明帳戶可被還原，但 zkProof 證明是用 Google 認證過的 Gmail 來產生（或是 Passkey），再拿到鏈上證明將 Account 存取權要回來

import * as React from "react";
import * as Ethers from "ethers";
import * as Helpers from "../helpers/helpers";

import { log, defaultPasskey, InputId } from "../helpers/helpers";

import * as WebauthnBrowser from "@simplewebauthn/browser";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

// 此套件沒有更進一步解析 authData，故不再採用
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticators.ts#L33-L41
// import * as WebauthnPass from "@passwordless-id/webauthn";

import * as typesVerifyPasskey from "contracts/typechain-types/factories/contracts/VerifyPasskey__factory";

export const WebauthnHardhat = () => {
  const [authAttach, setAuthAttach] =
    React.useState<WebauthnTypes.AuthenticatorAttachment>(
      defaultPasskey.authenticatorAttachment
    );
  const [authAttachChecked, setAuthAttachChecked] = React.useState<boolean>(
    false // false = "cross-platform", true = "platform"
  );

  // -----------------------------
  // -- Create and Sign Message by Passkey --
  // -----------------------------

  const handleCreateAndGetPasskeyDepList: React.DependencyList = [
    authAttach,
    authAttachChecked,
  ];

  const handleCreateAndGetPasskey = React.useCallback(async () => {
    // -------------------------------
    // -- create 註冊一組新的 Passkey --
    // -------------------------------

    // let challenge = userOpHash;
    const challengeCreate = Ethers.keccak256("0x1234");
    log("challengeCreate", challengeCreate);

    const challengeCreateBase64 = Helpers.hexToBase64URLString(challengeCreate);
    log("challengeCreateBase64", challengeCreateBase64);

    const challengeGet = Ethers.keccak256("0x5678");
    log("challengeGet", challengeGet);

    const challengeGetBase64 = Helpers.hexToBase64URLString(challengeGet);
    log("challengeGetBase64", challengeGetBase64);

    const user = "Irara Chen";

    // Create Passkey
    const registrationResponseJSON = await Helpers.createPasskey(
      user,
      challengeCreateBase64,
      authAttach
    );

    // 解析 authData
    const attestationObject =
      registrationResponseJSON.response.attestationObject;

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

    // --------------------------------------
    // -- get 使用 Passkey 對 challenge 簽名 --
    // --------------------------------------

    // 註：打 ☆ 者：表示確定有在 Demo 中出現：
    // https://mumbai.polygonscan.com/tx/0x701cf3790cce6ae20190be90518c8f8430a3c542a40993e84fe6b37d6d4837de

    const abi = Ethers.AbiCoder.defaultAbiCoder();

    // Get Passkey
    const authenticationResponseJSON = await Helpers.getPasskey(
      challengeGetBase64,
      credentialID
    );

    log(
      "clientExtensionResults",
      authenticationResponseJSON.clientExtensionResults
    );

    // 取得 authenticatorData
    const authenticatorDataBase64 =
      authenticationResponseJSON.response.authenticatorData;
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
    const clientDataJSONBase64 =
      authenticationResponseJSON.response.clientDataJSON;

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
      Helpers.splitClientDataJSONUtf8(clientDataJSONUtf8);

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
    const signatureBase64 = authenticationResponseJSON.response.signature;

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

    const [x, y, r, s]: bigint[] = abi.decode(
      ["uint256", "uint256", "uint256", "uint256"],
      encodedXYRS // = concatXYRS
    );

    console.log(`x: ${x}\ny: ${y}\nr: ${r}\ns: ${s}`);

    // -----------------------------------
    // -- Verify Signature via Contract --
    // -----------------------------------

    const clientDataJSONPack = abi.encode(
      ["string", "string"],
      [clientDataJSONPre, clientDataJSONPost]
    );
    log("clientDataJSONPack", clientDataJSONPack);

    const verifyPasskeyAddress = import.meta.env.VITE_HARDHAT_PASSKEY_ADDRESS;

    const provider = new Ethers.JsonRpcProvider(
      `${import.meta.env.VITE_PROVIDER_LOCAL}`
    );

    const verifyPasskeyContract =
      typesVerifyPasskey.VerifyPasskey__factory.connect(
        verifyPasskeyAddress,
        provider
      );

    const challengeGetBase64FromContract = await verifyPasskeyContract.base64(
      challengeGet
    );
    log("challengeGetBase64FromContract", challengeGetBase64FromContract);

    const sigResult = await verifyPasskeyContract.verifySignature(
      x,
      y,
      r,
      s,
      authenticatorDataHex, // ☆
      clientDataJSONPack, // ☆？
      challengeGet
    );
    log("sigResult", sigResult);

    // ...
  }, handleCreateAndGetPasskeyDepList);

  // ---------------------
  // --- Input Handler ---
  // ---------------------

  const handleInputChangeDepList: React.DependencyList = [
    authAttachChecked,
    authAttach,
  ];

  const handleInputChange = React.useCallback(
    (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
      // 更新 Input value
      const { id, value } = event.target;
      switch (id) {
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
      <div className="w-5/6 m-auto p-3 border-2 border-red-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">
          2. WebAuthN Hardhat All in one
        </h1>
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
            onClick={handleCreateAndGetPasskey}
            className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Create And Sign Challenge
          </button>
        </div>
      </div>
    </>
  );
};
