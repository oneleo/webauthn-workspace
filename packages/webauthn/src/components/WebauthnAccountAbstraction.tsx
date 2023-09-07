import * as React from "react";
// Refer to https://dev.to/kalush89/how-to-parse-html-string-in-react-53fh
import * as ReactParser from "html-react-parser";
import * as Ethers from "ethers";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";
import * as WebauthnBrowser from "@simplewebauthn/browser";

import * as Helpers from "../helpers/helpers";

import * as typesERC20 from "../../typechain-types/factories/@openzeppelin/contracts/token/ERC20/ERC20__factory";
import * as typesFactoryEntryPoint from "../../typechain-types/factories/@account-abstraction/contracts/core/EntryPoint__factory";
import * as typesFactoryAccountFactory from "../../typechain-types/factories/contracts/core/PasskeyManagerFactory.sol/PassKeyManagerFactory__factory";
import * as typesFactoryAccount from "../../typechain-types/factories/contracts/core/PasskeyManager__factory";
import * as typesVerifyPasskey from "../../typechain-types/factories/contracts/VerifyPasskey__factory";

import { log, defaultPasskey, InputId } from "../helpers/helpers";

const debug = true;

const usdcAddress = import.meta.env.VITE_USDC_ADDRESS;
const entryPointAddress = import.meta.env.VITE_ENTRY_POINT_ADDRESS;
const accountFactoryAddress = import.meta.env.VITE_ACCOUNT_FACTORY_ADDRESS;
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
  const [credentialIdSelectArray, setCredentialIdSelectArray] = React.useState<
    string[]
  >([]);
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
  const [accountAddress, setAccountAddress] =
    React.useState<Ethers.AddressLike>(Ethers.ZeroAddress);

  // ------------------------------
  // --- Create Passkey Handler ---
  // ------------------------------

  const handleCreatePasskeyDepList: React.DependencyList = [
    user,
    challengeCreate,
    authAttach,
    accountSalt,
    credentialIdSelectArray,
  ];

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-registration
  const handleCreatePasskey = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeCreate;

    // 建立唯一的 User 資訊
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

    // Create Passkey
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

    // 紀錄 credentialId 至 React Hook
    setCredentialId(credentialIdBase64);
    const cisa = credentialIdSelectArray;
    cisa.push(
      `<option value="${credentialIdBase64}">${credentialIdBase64}</option>`
    );
    // 注意：要讓 React 確實觸發 re-render，需將 Array State 解開更新
    // https://stackoverflow.com/questions/56266575/why-is-usestate-not-triggering-re-render
    setCredentialIdSelectArray([...cisa]);

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

    // 取得 USDC 合約實例
    const usdcContract = typesERC20.ERC20__factory.connect(
      usdcAddress,
      provider
    );

    // 取得 entryPoint 合約實例
    const entryPointContract =
      typesFactoryEntryPoint.EntryPoint__factory.connect(
        entryPointAddress,
        provider
      );

    // 取得 accountFactory 合約實例
    const accountFactoryContract =
      typesFactoryAccountFactory.PassKeyManagerFactory__factory.connect(
        accountFactoryAddress,
        provider
      );

    // 模擬合約執行以取得 accountAddress
    // 註：若直接執行 Write 合約是不會有想要的返回值的
    // https://github.com/ethers-io/ethers.js/issues/1102
    const createAccountStaticCall = await accountFactoryContract
      .connect(accountFactoryOwner)
      .createAccount.staticCall(
        accountSalt,
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    setAccountAddress(createAccountStaticCall);

    // 確實建立 PasskeyAccount 合約
    const createAccountResponse = await accountFactoryContract
      .connect(accountFactoryOwner)
      .createAccount(
        accountSalt,
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    await createAccountResponse.wait();

    // 取得 PasskeyAccount 實例
    const accountContract = typesFactoryAccount.PasskeyManager__factory.connect(
      createAccountStaticCall,
      provider
    );

    // 轉 ETH 至 PasskeyAccount 合約
    const sendAccountEthResponse = await accountOwner.sendTransaction({
      to: accountContract.target,
      ...gasOverridesWithValue,
    });

    await sendAccountEthResponse.wait();

    // 取得 USDC 位數
    const usdcDecimals = await usdcContract.decimals();

    // 轉 USDC 至 PasskeyAccount 合約
    const sendAccountUsdcResponse = await usdcContract
      .connect(accountOwner)
      .transfer(
        accountContract.target,
        Ethers.parseUnits("999", usdcDecimals),
        gasOverrides
      );

    await sendAccountUsdcResponse.wait();

    // PasskeyAccount 合約存 ETH 至 entryPoint 合約
    // 以及再轉 ETH 至 PasskeyAccount 合約
    const addAccountDepositResponse = await accountContract
      .connect(accountOwner)
      .addDeposit(gasOverridesWithValue);

    await addAccountDepositResponse.wait();

    //（不採用：得到的地址都是 accountFactory 地址）透過 accountFactoryContract 取得 PasskeyAccountAddress
    // 註 1：要注意 Ethers V6 合約實例內建 getAddress() 不要與 accountFactory 合約的 getAddress() 搞混
    // 註 2：此函數可在 createAccount() 之前執行，可預先取得 Account 地址
    // const accountAddressFromFactory = await accountFactoryContract
    //   // .connect(accountFactoryOwner)
    //   .getAddress(
    //     accountSalt,
    //     credentialIdBase64,
    //     credentialPublicKeyXUint256,
    //     credentialPublicKeyYUint256
    //   );

    // 取得 PasskeyAccount 合約的 ETH 餘額
    const getAccountEthResponse = await provider.getBalance(
      accountContract.target
    );

    // 取得 PasskeyAccount 合約的 USDC 餘額
    const getAccountUsdcResponse = await usdcContract.balanceOf(
      accountContract.target
    );

    // 取得 PasskeyAccount 合約在 entryPoint 合約中的餘額
    const getAccountDepositsResponse = await entryPointContract.deposits(
      accountContract.target
    );

    if (debug) {
      log("getAccountEthResponse", getAccountEthResponse);
      log("getAccountUsdcResponse", getAccountUsdcResponse);
      log("getAccountDepositsResponse", getAccountDepositsResponse);
      log("createAccountStaticCall", createAccountStaticCall);
    }

    // ...
  }, handleCreatePasskeyDepList);

  // -----------------------------------------------
  // --- Add Passkey To Account Contract Handler ---
  // -----------------------------------------------

  const handleAddPasskeyToContractDepList: React.DependencyList = [
    user,
    challengeCreate,
    authAttach,
    accountSalt,
    accountAddress,
    credentialIdSelectArray,
  ];

  const handleAddPasskeyToContract = React.useCallback(async () => {
    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeCreate;

    // 建立唯一的 User 資訊
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

    // Create Passkey
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

    // 紀錄 credentialId 至 React Hook
    const cisa = credentialIdSelectArray;
    cisa.push(
      `<option value="${credentialIdBase64}">${credentialIdBase64}</option>`
    );

    // 注意：要讓 React 確實觸發 re-render，需將 Array State 解開更新
    // https://stackoverflow.com/questions/56266575/why-is-usestate-not-triggering-re-render
    setCredentialIdSelectArray([...cisa]);

    // Parse authenticatorData
    const parsedAuthData = Helpers.parseAuthenticatorData(
      Helpers.decodeAttestationObject(
        Helpers.isoBase64URL.toBuffer(
          registrationResponseJSON.response.attestationObject
        )
      ).get("authData")
    );

    // 取得 credentialPublicKeyY
    // 註：只能在 create 註冊階段才能取得
    const credentialPublicKeyXUint256 = abi.decode(
      ["uint256"],
      abi.encode(
        ["bytes32"],
        [
          Helpers.base64URLStringToHex(
            Helpers.isoBase64URL.fromBuffer(
              parsedAuthData.credentialPublicKeyX!
            )
          ),
        ]
      )
    )[0] as bigint;

    // 取得 credentialPublicKeyY
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyYUint256 = abi.decode(
      ["uint256"],
      abi.encode(
        ["bytes32"],
        [
          Helpers.base64URLStringToHex(
            Helpers.isoBase64URL.fromBuffer(
              parsedAuthData.credentialPublicKeyY!
            )
          ),
        ]
      )
    )[0] as bigint;

    if (debug) {
      log("credentialIdBase64", credentialIdBase64);
      log("credentialIdKeccak256", credentialIdKeccak256);
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

    // 取得 PasskeyAccount 實例
    const accountContract = typesFactoryAccount.PasskeyManager__factory.connect(
      accountAddress as string,
      provider
    );

    // 增加 Passkey 至 PasskeyAccount
    const addPasskeyResponse = await accountContract
      .connect(accountOwner)
      .addPasskey(
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    await addPasskeyResponse.wait();

    if (debug) {
      const knownEncodedIdHashes: string[] = [];
      // 取得所有已註冊進合約的 credentialID
      for (let i = 0; i < cisa.length; i++) {
        knownEncodedIdHashes.push(
          await accountContract.KnownEncodedIdHashes(i)
        );
      }
      log("knownEncodedIdHashes", knownEncodedIdHashes);
    }
    // ...
  }, handleAddPasskeyToContractDepList);

  // ---------------------------
  // --- Get Passkey Handler ---
  // ---------------------------

  const handleGetPasskeyDepList: React.DependencyList = [
    challengeGet,
    credentialId,
    credentialIdSelectArray,
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

    // 在 Hardhat 階段取得 USDC
    // 在 Passkey Create 階段將 ETH、USDC 打到 Account
    // 在 Passkey Get 階段，通過驗證後，將 USDC 打回 accountOwner

    const verifyPasskeyContract =
      typesVerifyPasskey.VerifyPasskey__factory.connect(
        verifyPasskeyAddress,
        provider
      );

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
    accountSalt,
    challengeGet,
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

      // ...
    },
    handleInputChangeDepList
  );

  const handleSelectChangeDepList: React.DependencyList = [
    credentialId,
    credentialIdSelectArray,
  ];

  const handleSelectChange = React.useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>) => {
      // 更新 Select value
      const { id, value } = event.target;
      switch (id) {
        case InputId[InputId.credentialId]:
          setCredentialId(value);
          break;
        default:
          break;
      }
      console.log(`Select: ${id} = ${value}`);

      // ...
    },
    handleSelectChangeDepList
  );

  return (
    <>
      <div className="w-5/6 m-auto p-3 border-2 border-yellow-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">
          4. WebAuthN Account Abstraction
        </h1>
        <h2 className="text-2xl font-bold">Create Passkey</h2>
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
            Account Address
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${accountAddress}`}</span>
        </div>
        <h2 className="text-2xl font-bold">Get Passkey</h2>
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
            Credentials Registered
          </span>
          <select
            id={`${InputId[InputId.credentialId]}`}
            value={`${credentialId}`}
            onChange={handleSelectChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          >
            {ReactParser.default(credentialIdSelectArray.join(""))}
          </select>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <button
            onClick={handleCreatePasskey}
            className="order-1 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Create Passkey
          </button>
          <button
            onClick={handleAddPasskeyToContract}
            className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Add Passkey
          </button>
          <button
            onClick={handleGetPasskey}
            className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Get Passkey
          </button>
        </div>
      </div>
    </>
  );
};
