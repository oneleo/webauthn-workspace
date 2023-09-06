import * as React from "react";
import * as Ethers from "ethers";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";
import * as WebauthnBrowser from "@simplewebauthn/browser";

import * as Helpers from "../helpers/helpers";
import * as typesFactoryAccountFactory from "../../typechain-types/factories/contracts/core/PasskeyManagerFactory.sol/PassKeyManagerFactory__factory";
import * as typesVerifyPasskey from "../../typechain-types/factories/contracts/VerifyPasskey__factory";

import { log, defaultPasskey, InputId } from "../helpers/helpers";

const debug = true;

const accountFactoryContractAddress = import.meta.env
  .VITE_ACCOUNT_FACTORY_ADDRESS;
const verifyPasskeyAddress = import.meta.env.VITE_VERIFY_PASSKEY_ADDRESS;
const provider = new Ethers.JsonRpcProvider(`${import.meta.env.VITE_PROVIDER}`);

const signers = Ethers.HDNodeWallet.fromMnemonic(
  Ethers.Mnemonic.fromPhrase(import.meta.env.VITE_MNEMONIC),
  "m/44'/60'/0'/0"
).connect(provider);

const [
  accountOwner,
  bundlerOwner,
  erc1967ProxyOwner,
  accountFactoryOwner,
  paymasterOwner,
  entryPointOwner,
] = [
  signers.deriveChild(0),
  signers.deriveChild(1),
  signers.deriveChild(2),
  signers.deriveChild(3),
  signers.deriveChild(4),
  signers.deriveChild(5),
];

const abi = Ethers.AbiCoder.defaultAbiCoder();

export const WebauthnAccountAbstraction = () => {
  const [user, setUser] = React.useState<string>("user");
  const [challengeCreate, setChallengeCreate] = React.useState<string>(
    Helpers.hexToBase64URLString(Ethers.keccak256("0x123456"))
  );
  const [challengeGet, setChallengeGet] = React.useState<string>(
    Helpers.hexToBase64URLString(Ethers.keccak256("0x456789"))
  );
  const [credentialId, setCredentialId] = React.useState<string>("");
  const [authAttach, setAuthAttach] =
    React.useState<WebauthnTypes.AuthenticatorAttachment>(
      defaultPasskey.authenticatorAttachment
    );
  const [authAttachChecked, setAuthAttachChecked] = React.useState<boolean>(
    false // false = "cross-platform", true = "platform"
  );
  const [accountSalt, setAccountSalt] = React.useState<bigint>(
    BigInt(333666999)
  );

  // ------------------------------
  // --- Create Passkey Handler ---
  // ------------------------------

  const handleCreatePasskeyDepList: React.DependencyList = [
    user,
    challengeCreate,
    authAttach,
    accountSalt,
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

    const credentialIdBase64 = registrationResponseJSON.id;

    const credentialIdKeccak256 = Ethers.keccak256(
      Ethers.solidityPacked(["string"], [credentialIdBase64])
    );

    setCredentialId(credentialIdBase64);

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

    const credentialPublicKeyXUint256 = abi.decode(
      ["uint256"],
      abi.encode(["bytes32"], [credentialPublicKeyXHex])
    )[0] as bigint;

    // 取得 credentialPublicKeyY
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyYBase64 = Helpers.isoBase64URL.fromBuffer(
      parsedAuthData.credentialPublicKeyY!
    );

    const credentialPublicKeyYHex = Helpers.base64URLStringToHex(
      credentialPublicKeyYBase64
    );

    const credentialPublicKeyYUint256 = abi.decode(
      ["uint256"],
      abi.encode(["bytes32"], [credentialPublicKeyYHex])
    )[0] as bigint;

    if (debug) {
      console.warn(`+++ Create Passkey +++`);
      log("* credentialIdBase64", credentialIdBase64);
      log("credentialIdKeccak256", credentialIdKeccak256);
      log(
        "* attestationObject > authData > credentialPublicKeyXHex",
        credentialPublicKeyXHex
      );
      log(
        "* attestationObject > authData > credentialPublicKeyXUint256",
        credentialPublicKeyXUint256
      );
      log(
        "* attestationObject > authData > credentialPublicKeyYHex",
        credentialPublicKeyYHex
      );
      log(
        "* attestationObject > authData > credentialPublicKeyYUint256",
        credentialPublicKeyYUint256
      );
    }

    // 接下來會與合約互動
    // Declare the gas overrides argument.
    // The gasLimit should be sufficiently large to avoid the
    // "Error: Transaction reverted: trying to deploy a contract whose code is too large" error.
    const feeData = await provider.getFeeData();

    const gasOverrides: Ethers.Overrides = {
      gasLimit: BigInt(9999999),
      maxFeePerGas: feeData.maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
    };

    // Declare the gas overrides argument.
    const gasOverridesWithValue: Ethers.Overrides = {
      ...gasOverrides,
      value: Ethers.parseEther("9"),
    };

    // 取得 accountFactory 合約實例
    const accountFactoryContract =
      typesFactoryAccountFactory.PassKeyManagerFactory__factory.connect(
        accountFactoryContractAddress,
        provider
      );

    // 取得 PasskeyAccountAddress
    // 註：因為 Ethers V6 合約實例內建 getAddress() 與 accountFactory 合約 getAddress() 衝突
    const accountAddressPredict = accountFactoryContract
      // .connect(accountFactoryOwner)
      .getAddress(
        accountSalt,
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256
      );

    // 為什麼是空值？

    // 取得 verifyPasskey 合約實例
    const verifyPasskeyContract =
      typesVerifyPasskey.VerifyPasskey__factory.connect(
        verifyPasskeyAddress,
        provider
      );

    // 模擬合約執行
    // const addPaskeyResult = await verifyPasskeyContract
    // .connect(accountOwner)
    // .addPasskey.staticCall(
    //   credentialIdBase64,
    //   credentialPublicKeyXUint256,
    //   credentialPublicKeyYUint256
    // );

    // 確定合約執行
    const addPaskeyResult = await verifyPasskeyContract
      .connect(accountOwner)
      .addPasskey(
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    if (debug) {
      log("accountAddressPredict", accountAddressPredict);
      log("addPaskeyResult", addPaskeyResult);
    }

    // ...
  }, handleCreatePasskeyDepList);

  // ---------------------------
  // --- Get Passkey Handler ---
  // ---------------------------

  const handleGetPasskeyDepList: React.DependencyList = [
    challengeGet,
    credentialId,
  ];

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-authentication
  const handleGetPasskey = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeGet;
    const challengeHex = Helpers.base64URLStringToHex(challengeBase64);

    const authenticationResponseJSON: WebauthnTypes.AuthenticationResponseJSON =
      await WebauthnBrowser.startAuthentication({
        allowCredentials: [
          { id: credentialId, type: defaultPasskey.pubKeyCredType },
        ] as WebauthnTypes.PublicKeyCredentialDescriptorJSON[],
        userVerification: defaultPasskey.userVerificationRequirement,
        challenge: challengeBase64,
      } as WebauthnTypes.PublicKeyCredentialRequestOptionsJSON);

    // 取得 credentialIdKeccak256
    const credentialIdKeccak256 = Ethers.keccak256(
      Ethers.solidityPacked(["string"], [credentialId])
    );

    const authenticatorDataBase64 =
      authenticationResponseJSON.response.authenticatorData;

    const authenticatorDataHex = Helpers.base64URLStringToHex(
      authenticatorDataBase64
    );

    const clientDataJSONBase64 =
      authenticationResponseJSON.response.clientDataJSON;

    const clientDataJSONUtf8 =
      Helpers.isoBase64URL.toString(clientDataJSONBase64);

    // Parse clientDataJSON
    const parsedClientDataJSONUtf8 =
      Helpers.splitClientDataJSONUtf8(clientDataJSONUtf8);

    const clientDataJSONPreUtf8 = parsedClientDataJSONUtf8.clientDataJSONPre;

    const clientDataJSONPreHex = Helpers.utf8StringToHex(clientDataJSONPreUtf8);

    const clientDataJSONPostUtf8 = parsedClientDataJSONUtf8.clientDataJSONPost;

    const clientDataJSONPostHex = Helpers.utf8StringToHex(
      clientDataJSONPostUtf8
    );

    const clientDataJSONPack = abi.encode(
      ["string", "string"],
      [clientDataJSONPreUtf8, clientDataJSONPostUtf8]
    );

    const signatureBase64 = authenticationResponseJSON.response.signature;

    // Parse signature
    const parsedSignature = Helpers.parseEC2Signature(
      Helpers.isoBase64URL.toBuffer(signatureBase64)
    );

    const signatureRHex = `0x${Helpers.isoUint8Array.toHex(parsedSignature.r)}`;

    const signatureRUint256 = abi.decode(
      ["uint256"],
      abi.encode(["bytes32"], [signatureRHex])
    )[0] as bigint;

    const signatureSHex = `0x${Helpers.isoUint8Array.toHex(parsedSignature.s)}`;

    const signatureSUint256 = abi.decode(
      ["uint256"],
      abi.encode(["bytes32"], [signatureSHex])
    )[0] as bigint;

    const verifyPasskeyContract =
      typesVerifyPasskey.VerifyPasskey__factory.connect(
        verifyPasskeyAddress,
        provider
      );

    if (debug) {
      console.warn(`+++ Get Passkey +++`);
      log("credentialID", credentialId);
      log("* credentialIDKeccak256", credentialIdKeccak256);
      log("challengeBase64", challengeBase64);
      log("* challengeHex", challengeHex);
      log(
        "authenticationResponseJSON > authenticatorDataBase64",
        authenticatorDataBase64
      );
      log(
        "* authenticationResponseJSON > authenticatorDataHex",
        authenticatorDataHex
      );
      log(
        "* authenticationResponseJSON > clientDataJSON > preUtf8",
        clientDataJSONPreUtf8
      );
      log(
        "* authenticationResponseJSON > clientDataJSON > preHex",
        clientDataJSONPreHex
      );
      log(
        "* authenticationResponseJSON > clientDataJSON > postUtf8",
        clientDataJSONPostUtf8
      );
      log(
        "authenticationResponseJSON > clientDataJSON > postHex",
        clientDataJSONPostHex
      );
      log("authenticationResponseJSON > signature > rHex", signatureRHex);
      log(
        "* authenticationResponseJSON > signature > rUint256",
        signatureRUint256
      );
      log("* authenticationResponseJSON > signature > sHex", signatureSHex);
      log(
        "authenticationResponseJSON > signature > sUint256",
        signatureSUint256
      );
    }

    const sigResult = await verifyPasskeyContract.validateSignature(
      signatureRUint256,
      signatureSUint256,
      authenticatorDataHex, // ☆
      clientDataJSONPack, // ☆？
      credentialIdKeccak256,
      challengeHex
    );
    log("sigResult", sigResult);

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
        case InputId[InputId.accountSalt]:
          setAccountSalt(BigInt(value));
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
      <div className="w-4/6 m-auto p-3 border-2 border-yellow-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">
          4. WebAuthN Account Abstraction
        </h1>
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
            Account Salt
          </span>
          <input
            type="text"
            id={`${InputId[InputId.accountSalt]}`}
            value={`${accountSalt}`}
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
