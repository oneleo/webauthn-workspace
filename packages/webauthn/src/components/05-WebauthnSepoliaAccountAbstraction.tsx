import * as React from "react";
// Refer to https://dev.to/kalush89/how-to-parse-html-string-in-react-53fh
import * as ReactParser from "html-react-parser";
import * as Ethers from "ethers";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

import * as Helpers from "../helpers/helpers";
import { log, defaultPasskey, InputId } from "../helpers/helpers";

import * as typesERC20 from "../../typechain-types/factories/@openzeppelin/contracts/token/ERC20/ERC20__factory";
import * as typesFactoryEntryPoint from "../../typechain-types/factories/@account-abstraction/contracts/core/EntryPoint__factory";
import * as typesFactoryAccountFactory from "../../typechain-types/factories/contracts/core/PasskeyManagerFactory.sol/PassKeyManagerFactory__factory";
import * as typesFactoryAccount from "../../typechain-types/factories/contracts/core/PasskeyManager__factory";

const debug = true;

const abi = Ethers.AbiCoder.defaultAbiCoder();

const usdcAddress = import.meta.env.VITE_SEPOLIA_USDC_ADDRESS;
const entryPointAddress = import.meta.env.VITE_ENTRY_POINT_ADDRESS;
const accountFactoryAddress = import.meta.env
  .VITE_SEPOLIA_ACCOUNT_FACTORY_ADDRESS;

const provider = new Ethers.JsonRpcProvider(`${import.meta.env.VITE_PROVIDER}`);

const signers = Ethers.HDNodeWallet.fromMnemonic(
  Ethers.Mnemonic.fromPhrase(import.meta.env.VITE_MNEMONIC),
  "m/44'/60'/0'/0"
).connect(provider);

const [
  accountNonPasskeyOwner,
  bundlerOwner,
  erc1967ProxyOwner,
  accountFactoryOwner,
  paymasterOwner,
  entryPointOwner,
  receiver,
] = [
  signers.deriveChild(0),
  signers.deriveChild(1),
  signers.deriveChild(2),
  signers.deriveChild(3),
  signers.deriveChild(4),
  signers.deriveChild(5),
  signers.deriveChild(20),
];

const defaultHardhatBalance = Ethers.parseEther("0");
const defaultOverridesValue = Ethers.parseEther("0.03");
const defaultAccountSalt = BigInt("333666999");
const defaultUserOp: Helpers.UserOperationStruct = {
  sender: Ethers.ZeroAddress,
  nonce: BigInt("0"),
  initCode: "0x",
  callData: "0x",
  // callGasLimit 不能 > gasLimit 否則 AA95 out of gas
  callGasLimit: BigInt("10000000"),
  // verificationGasLimit 不能 < 1,000,000 否則 AA23 reverted (or OOG)
  verificationGasLimit: BigInt("1000000"),
  // preVerificationGas 若 < 10,000,000，則 Bundler 的收益可能是負的
  preVerificationGas: BigInt("10000000"),
  maxFeePerGas: Ethers.parseUnits("10", "gwei"),
  maxPriorityFeePerGas: Ethers.parseUnits("0.1", "gwei"),
  paymasterAndData: "0x",
  signature: "0x",
};

export const WebauthnSepoliaAccountAbstraction = () => {
  const [user, setUser] = React.useState<string>("user");
  const [challengeCreate, setChallengeCreate] = React.useState<string>(
    Helpers.hexToBase64URLString(Ethers.keccak256("0x123456"))
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
  const [usdcDecimals, setUsdcDecimals] = React.useState<bigint>(BigInt(0));
  const [accountSalt, setAccountSalt] =
    React.useState<bigint>(defaultAccountSalt);
  const [accountAddress, setAccountAddress] =
    React.useState<Ethers.AddressLike>(Ethers.ZeroAddress);
  const [accountNonce, setAccountNonce] = React.useState<bigint>(BigInt(0));
  const [accountEthBalance, setAccountEthBalance] = React.useState<bigint>(
    defaultOverridesValue
  );
  const [accountEthEntryPointBalance, setAccountEthEntryPointBalance] =
    React.useState<bigint>(defaultOverridesValue);
  const [accountEthEntryPointDiff, setAccountEthEntryPointDiff] =
    React.useState<bigint>(BigInt(0));
  const [accountUsdcBalance, setAccountUsdcBalance] = React.useState<bigint>(
    BigInt(0)
  );
  const [receiverEthBalance, setReceiverEthBalance] = React.useState<bigint>(
    BigInt(0)
  );
  const [receiverUsdcBalance, setReceiverUsdcBalance] = React.useState<bigint>(
    BigInt(0)
  );
  const [bundlerOwnerEthBalance, setBundlerOwnerEthBalance] =
    React.useState<bigint>(defaultHardhatBalance);
  const [bundlerOwnerEthDiff, setBundlerOwnerEthDiff] = React.useState<bigint>(
    BigInt(0)
  );
  const [gasUsed, setGasUsed] = React.useState<bigint>(BigInt(0));
  const [baseFeePerGas, setBaseFeePerGas] = React.useState<bigint>(BigInt(0));
  const [maxPriorityFeePerGas, setMaxPriorityFeePerGas] =
    React.useState<bigint>(BigInt(0));
  const [totalFee, setTotalFee] = React.useState<bigint>(BigInt(0));
  // preVerificationGas: BigInt("10000000"),
  // maxFeePerGas: Ethers.parseUnits("10", "gwei"),
  // maxPriorityFeePerGas: Ethers.parseUnits("0.1", "gwei"),
  const [userOpGasUsed, setUserOpGasUsed] = React.useState<bigint>(BigInt(1));
  const [userOpPreVerificationGas, setUserOpPreVerificationGas] =
    React.useState<bigint>(BigInt(0));
  const [userOpBaseFeePerGas, setUserOpBaseFeePerGas] = React.useState<bigint>(
    BigInt(0)
  );
  const [userOpMaxPriorityFeePerGas, setUserOpMaxPriorityFeePerGas] =
    React.useState<bigint>(BigInt(0));
  const [userOpTotalFee, setUserOpTotalFee] = React.useState<bigint>(BigInt(0));

  const [buttonDisabled, setButtonDisabled] = React.useState<boolean>(false);

  // --------------------
  // --- Render Timer ---
  // --------------------

  const useEffectTimerDepList: React.DependencyList = [
    accountAddress,
    accountEthEntryPointBalance,
    bundlerOwnerEthBalance,
  ];

  React.useEffect(() => {
    // 如果 accountAddress 為 0x0 就不執行
    if (accountAddress === Ethers.ZeroAddress) {
      return;
    }

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

    // 取得 PasskeyAccount 合約實例
    const accountContract = typesFactoryAccount.PasskeyManager__factory.connect(
      accountAddress as string,
      provider
    );

    // 放在 React.useEffect() 中的非同步函數
    const asyncFunction = async () => {
      // 偵測鏈上是否已部署此 Account 合約：失敗
      if ((await provider.getCode(accountContract.target)) === "0x") {
        setAccountNonce(BigInt(0));
        setAccountEthBalance(BigInt(0));
        setAccountEthEntryPointDiff(BigInt(0));
        setAccountEthEntryPointBalance(BigInt(0));
        setAccountUsdcBalance(BigInt(0));
        setReceiverEthBalance(BigInt(0));
        setReceiverUsdcBalance(BigInt(0));
        setBundlerOwnerEthDiff(BigInt(0));
        setBundlerOwnerEthBalance(BigInt(0));
      }

      // 偵測鏈上是否已部署此 Account 合約：成功
      if ((await provider.getCode(accountContract.target)) !== "0x") {
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

        // 取得 PasskeyAccount 合約的 Nonce 值
        const getAccountNonceResponse = await accountContract.getNonce();

        // 取得 Receiver 的 ETH 餘額
        const getReceiverEthResponse = await provider.getBalance(
          receiver.address
        );

        // 取得 Receiver 合約的 USDC 餘額
        const getReceiverUsdcResponse = await usdcContract.balanceOf(
          receiver.address
        );

        // 取得 BundlerOwner 的 ETH 餘額
        const getBundlerOwnerEthResponse = await provider.getBalance(
          bundlerOwner.address
        );

        // 設置對應值
        setAccountNonce(getAccountNonceResponse);
        setAccountEthBalance(getAccountEthResponse);
        setAccountUsdcBalance(getAccountUsdcResponse);
        if (getAccountDepositsResponse[0] !== accountEthEntryPointBalance) {
          setAccountEthEntryPointDiff(
            getAccountDepositsResponse[0] - accountEthEntryPointBalance
          );
        }
        setAccountEthEntryPointBalance(getAccountDepositsResponse[0]);
        setReceiverEthBalance(getReceiverEthResponse);
        setReceiverUsdcBalance(getReceiverUsdcResponse);
        if (getBundlerOwnerEthResponse !== bundlerOwnerEthBalance) {
          setBundlerOwnerEthDiff(
            getBundlerOwnerEthResponse - bundlerOwnerEthBalance
          );
        }
        setBundlerOwnerEthBalance(getBundlerOwnerEthResponse);
        // ...
      }
    };

    // 設置計數器
    let id = setInterval(() => {
      asyncFunction().catch((e) => console.log(e));
    }, 33333); // 每 3.333 秒執行一次

    // 這邊的 return 如同 componentWillUnmount() 函數
    // 當此時 useEffect 要 unmount 時會將目前的計數器 id 刪除
    // 好讓一個新的 useEffect 不會和舊的 useEffect 重複
    return () => {
      clearInterval(id);
    };

    // ...
  }, useEffectTimerDepList);

  // --------------
  // --- Helper ---
  // --------------

  // 清除 Gas 資訊
  const clearGasInfo = () => {
    setGasUsed(BigInt(0));
    setBaseFeePerGas(BigInt(0));
    setMaxPriorityFeePerGas(BigInt(0));
    setTotalFee(BigInt(0));
    setBundlerOwnerEthDiff(BigInt(0));

    setUserOpGasUsed(BigInt(1));
    setUserOpBaseFeePerGas(BigInt(0));
    setUserOpMaxPriorityFeePerGas(BigInt(0));
    setUserOpPreVerificationGas(BigInt(0));
    setUserOpTotalFee(BigInt(0));
  };

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
    // 操作開始，鎖定所有按鈕
    setButtonDisabled(true);

    // 清除 Gas 資訊
    clearGasInfo();

    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeCreate;

    // Create Passkey
    const registrationResponseJSON = await Helpers.createPasskey(
      user,
      challengeBase64,
      authAttach
    );

    const credentialIdBase64 = registrationResponseJSON.id;

    const credentialIdKeccak256 = Ethers.keccak256(
      Ethers.solidityPacked(["string"], [credentialIdBase64])
    );

    setCredentialId(credentialIdBase64);

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

    // 取得 credentialPublicKeyX
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyXHex = Helpers.base64URLStringToHex(
      Helpers.isoBase64URL.fromBuffer(parsedAuthData.credentialPublicKeyX!)
    );

    const credentialPublicKeyXUint256 = abi.decode(
      ["uint256"],
      abi.encode(["bytes32"], [credentialPublicKeyXHex])
    )[0] as bigint;

    // 取得 credentialPublicKeyY
    // 註：一樣只能在 create 註冊階段才能取得
    const credentialPublicKeyYHex = Helpers.base64URLStringToHex(
      Helpers.isoBase64URL.fromBuffer(parsedAuthData.credentialPublicKeyY!)
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
      gasLimit: BigInt(19999999),
      maxFeePerGas: feeData.maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
    };

    // Declare the gas overrides argument.
    const gasOverridesWithValue: Ethers.Overrides = {
      ...gasOverrides,
      value: defaultOverridesValue,
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

    log("accountNonPasskeyOwner", accountNonPasskeyOwner.address);
    log("bundlerOwner", bundlerOwner.address);
    log("accountFactoryAddress", accountFactoryAddress);

    // 模擬合約執行以取得 accountAddress
    // 註：若直接執行 Write 合約是不會有想要的返回值的
    // https://github.com/ethers-io/ethers.js/issues/1102
    const createAccountStaticCall = await accountFactoryContract
      .connect(bundlerOwner)
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
      .connect(bundlerOwner)
      .createAccount(
        accountSalt,
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    console.warn("Always waiting for the transaction to be mined...");

    await createAccountResponse.wait();

    // 取得完整交易資訊
    const createAccountReceipt = await provider.getTransactionReceipt(
      createAccountResponse.hash
    );

    // 如果取得交易資訊，則設置 Gas 資訊
    if (createAccountReceipt && createAccountResponse.maxPriorityFeePerGas) {
      // TotalFee = gasUsed * gasPrice = gasUsed * ( baseFee + maxPriority )
      // To miner = gasUsed * maxPriority
      // To burnt = gasUsed * bassFee = TotalFee - To miner
      setGasUsed(createAccountReceipt.gasUsed);
      setBaseFeePerGas(
        createAccountReceipt.gasPrice -
          createAccountResponse.maxPriorityFeePerGas
      );
      setMaxPriorityFeePerGas(createAccountResponse.maxPriorityFeePerGas);
      setTotalFee(createAccountReceipt.gasUsed * createAccountReceipt.gasPrice);
    }

    // 取得 PasskeyAccount 實例
    const accountContract = typesFactoryAccount.PasskeyManager__factory.connect(
      createAccountStaticCall,
      provider
    );

    // 轉 ETH 至 PasskeyAccount 合約
    const sendAccountEthResponse = await accountNonPasskeyOwner.sendTransaction(
      {
        to: accountContract.target,
        ...gasOverridesWithValue,
      }
    );

    await sendAccountEthResponse.wait();

    // 取得 USDC 位數
    const usdcDecimalsResponse = await usdcContract.decimals();
    setUsdcDecimals(usdcDecimalsResponse);

    // 轉 USDC 至 PasskeyAccount 合約
    const sendAccountUsdcResponse = await usdcContract
      .connect(accountNonPasskeyOwner)
      .transfer(
        accountContract.target,
        Ethers.parseUnits("999", usdcDecimalsResponse),
        gasOverrides
      );

    await sendAccountUsdcResponse.wait();

    // PasskeyAccount 合約存 ETH 至 entryPoint 合約
    // 以及再轉 ETH 至 PasskeyAccount 合約
    const addAccountDepositResponse = await accountContract
      .connect(accountNonPasskeyOwner)
      .addDeposit(gasOverridesWithValue);

    await addAccountDepositResponse.wait();

    //（不採用：得到的地址都是 accountFactory 地址）透過 accountFactoryContract 取得 PasskeyAccountAddress
    // 註 1：要注意 Ethers V6 合約實例內建 getAddress() 不要與 accountFactory 合約的 getAddress() 搞混
    // 註 2：此函數可在 createAccount() 之前執行，可預先取得 Account 地址
    // const accountAddressFromFactory = await accountFactoryContract
    //   // .connect(bundlerOwner)
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

    //（總是為 zero 地址）取得 PasskeyAccount 合約登記的 Owner
    // const getAccountOwnerResponse = await accountContract.owner();

    if (debug) {
      log("getAccountEthResponse", getAccountEthResponse);
      log("getAccountUsdcResponse", getAccountUsdcResponse);
      log("getAccountDepositsResponse", getAccountDepositsResponse);
      log("createAccountStaticCall", createAccountStaticCall);
    }
    // 操作完成，解鎖全部按鈕
    setButtonDisabled(false);

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
    // 清除 Gas 資訊
    clearGasInfo();

    // The challenge is produced by the server; see the Security Considerations
    const challengeBase64 = challengeCreate;

    // Create Passkey
    const registrationResponseJSON = await Helpers.createPasskey(
      user,
      challengeBase64,
      authAttach
    );

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
      console.warn(`+++ Add Passkey +++`);
      log("credentialIdBase64", credentialIdBase64);
      log("credentialIdKeccak256", credentialIdKeccak256);
    }

    // 接下來會與合約互動
    // Declare the gas overrides argument.
    // The gasLimit should be sufficiently large to avoid the
    // "Error: Transaction reverted: trying to deploy a contract whose code is too large" error.
    const feeData = await provider.getFeeData();

    const gasOverrides: Ethers.Overrides = {
      gasLimit: BigInt(19999999),
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
      .connect(accountNonPasskeyOwner)
      .addPasskey(
        credentialIdBase64,
        credentialPublicKeyXUint256,
        credentialPublicKeyYUint256,
        gasOverrides
      );

    await addPasskeyResponse.wait();

    // 取得完整交易資訊
    const addPasskeyReceipt = await provider.getTransactionReceipt(
      addPasskeyResponse.hash
    );

    // 如果取得交易資訊，則設置 Gas 資訊
    if (addPasskeyReceipt && addPasskeyResponse.maxPriorityFeePerGas) {
      // TotalFee = gasUsed * gasPrice = gasUsed * ( baseFee + maxPriority )
      // To miner = gasUsed * maxPriority
      // To burnt = gasUsed * bassFee = TotalFee - To miner
      setGasUsed(addPasskeyReceipt.gasUsed);
      setBaseFeePerGas(
        addPasskeyReceipt.gasPrice - addPasskeyResponse.maxPriorityFeePerGas
      );
      setMaxPriorityFeePerGas(addPasskeyResponse.maxPriorityFeePerGas);
      setTotalFee(addPasskeyReceipt.gasUsed * addPasskeyReceipt.gasPrice);
    }

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
    credentialId,
    credentialIdSelectArray,
    accountAddress,
    accountNonce,
    usdcDecimals,
  ];

  // 參考：https://w3c.github.io/webauthn/#sctn-sample-authentication
  const handleGetPasskey = React.useCallback(async () => {
    // 清除 Gas 資訊
    clearGasInfo();

    const feeData = await provider.getFeeData();

    const gasOverrides: Ethers.Overrides = {
      gasLimit: BigInt(19999999),
      maxFeePerGas: feeData.maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
    };

    // 取得 USDC 合約實例與介面
    const usdcContract = typesERC20.ERC20__factory.connect(
      usdcAddress,
      provider
    );

    const usdcInterface = typesERC20.ERC20__factory.createInterface();

    // 取得 entryPoint 合約實例
    const entryPointContract =
      typesFactoryEntryPoint.EntryPoint__factory.connect(
        entryPointAddress,
        provider
      );

    // 取得 PasskeyAccount 合約實例與介面
    const accountContract = typesFactoryAccount.PasskeyManager__factory.connect(
      accountAddress as string,
      provider
    );
    const accountInterface =
      typesFactoryAccount.PasskeyManager__factory.createInterface();

    // 轉送 USDC 範例參考：
    // https://4337.blocknative.com/ops/0x466860c58814ab8bbf884efd59682ac2dce11bd229cc922a4478582abcc70b57/0

    const executeArgs = [
      {
        // 組出 AccountContract 轉送 USDC 的 Calldata
        dest: usdcContract.target, // dest
        value: BigInt(0), // value
        func: usdcInterface.encodeFunctionData("transfer", [
          receiver.address,
          Ethers.parseUnits("1", usdcDecimals),
        ]), // func
      },
      {
        // 組出 AccountContract 轉送 ETH 的 Calldata
        dest: receiver.address, // dest
        value: Ethers.parseEther("1"), // value
        func: Ethers.getBytes("0x"), // func
      },
      {
        // 組出 AccountContract 轉送 ETH 的 Calldata
        dest: accountContract.target,
        value: Ethers.parseEther("0"),
        func: accountInterface.encodeFunctionData("execute", [
          receiver.address, // dest
          Ethers.parseEther("1"), // value
          Ethers.getBytes("0x"), // func
        ]),
      },
    ];

    const userOp: Helpers.UserOperationStruct = {
      ...defaultUserOp,
      sender: accountAddress as string,
      nonce: accountNonce,
      callData: accountInterface.encodeFunctionData("executeBatch", [
        [executeArgs[0].dest],
        [executeArgs[0].func],
      ]),
      // callData: accountInterface.encodeFunctionData("execute", [
      //   executeArgs[1].dest,
      //   executeArgs[1].value,
      //   executeArgs[1].func,
      // ])

      // callData: accountInterface.encodeFunctionData("executeBatch", [
      //   [executeArgs[2].dest],
      //   [executeArgs[2].func],
      // ])

      // ...
    };

    // 取得 userOpHash
    const userOpHashResponse = await entryPointContract.getUserOpHash(userOp);

    // The challenge is produced by the server; see the Security Considerations
    const challengeHex = userOpHashResponse;
    const challengeBase64 = Helpers.hexToBase64URLString(challengeHex);

    // Get Passkey
    const authenticationResponseJSON = await Helpers.getPasskey(
      credentialId,
      challengeBase64
    );

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

    userOp.signature = abi.encode(
      ["uint256", "uint256", "bytes", "string", "string", "bytes32"],
      [
        signatureRUint256,
        signatureSUint256,
        authenticatorDataHex,
        clientDataJSONPreUtf8, // "123", // AA23 reverted: PM07: Invalid signature
        clientDataJSONPostUtf8,
        credentialIdKeccak256,
      ]
    );

    const handleOpsResponse = await entryPointContract
      .connect(bundlerOwner)
      .handleOps([userOp], bundlerOwner.address, gasOverrides);

    await handleOpsResponse.wait();

    // 取得完整交易資訊
    const handleOpsReceipt = await provider.getTransactionReceipt(
      handleOpsResponse.hash
    );

    // 如果取得交易資訊，則設置 Gas 資訊
    if (handleOpsReceipt && handleOpsResponse.maxPriorityFeePerGas) {
      // TotalFee = gasUsed * gasPrice = gasUsed * ( baseFee + maxPriority )
      // To miner = gasUsed * maxPriority
      // To burnt = gasUsed * bassFee = TotalFee - To miner
      setGasUsed(handleOpsReceipt.gasUsed);
      setBaseFeePerGas(
        handleOpsReceipt.gasPrice - handleOpsResponse.maxPriorityFeePerGas
      );
      setMaxPriorityFeePerGas(handleOpsResponse.maxPriorityFeePerGas);
      setTotalFee(handleOpsReceipt.gasUsed * handleOpsReceipt.gasPrice);

      const userOpEventData = handleOpsReceipt.logs[2].data;
      const [nonce, success, actualGasCost, actualGasUsed] = abi.decode(
        ["uint256", "bool", "uint256", "uint256"],
        userOpEventData
      );

      // 取得 UserOp 相關 Gas 資訊
      setUserOpTotalFee(actualGasCost);
      setUserOpGasUsed(actualGasUsed);
      setUserOpPreVerificationGas(BigInt(userOp.preVerificationGas));
      setUserOpBaseFeePerGas(
        (actualGasCost as bigint) / (actualGasUsed as bigint) -
          BigInt(userOp.maxPriorityFeePerGas)
      );
      setUserOpMaxPriorityFeePerGas(BigInt(userOp.maxPriorityFeePerGas));
    }

    if (debug) {
      Helpers.logUserOp(userOp);
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
    accountSalt,
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
      <div className="w-5/6 m-auto p-3 border-2 border-pink-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">
          5. WebAuthN Account Abstraction
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
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Account Nonce
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${accountNonce}`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Account ETH Balance
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatEther(
            accountEthBalance
          )} ETH`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Account USDC Balance
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatUnits(
            accountUsdcBalance,
            usdcDecimals
          )} USDC`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Account deposit EntryPoint Balance
          </span>
          <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatEther(
            accountEthEntryPointBalance
          )} ETH`}</span>
          <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-red-500">{`(${Ethers.formatEther(
            accountEthEntryPointDiff
          )} ETH)`}</span>
        </div>
        <h2 className="text-2xl font-bold">Get Passkey</h2>
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
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Receiver ETH Balance
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatEther(
            receiverEthBalance
          )} ETH`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Receiver USDC Balance
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatUnits(
            receiverUsdcBalance,
            usdcDecimals
          )} USDC`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-emerald-500">
            Bundler Owner ETH Balance
          </span>
          <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatEther(
            bundlerOwnerEthBalance
          )} ETH`}</span>
          <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-emerald-500">{`(+ ${Ethers.formatEther(
            bundlerOwnerEthDiff
          )} ETH)`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            gasUsed
          </span>
          <span className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">{`${gasUsed}`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            Base Fee Per Gas
          </span>
          <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${baseFeePerGas} Wei`}</span>
          <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`x gasUsed = ${Ethers.formatEther(
            gasUsed * baseFeePerGas
          )} ETH`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            maxPriorityFeePerGas
          </span>
          <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${maxPriorityFeePerGas} Wei`}</span>
          <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`x gasUsed = ${Ethers.formatEther(
            gasUsed * maxPriorityFeePerGas
          )} ETH`}</span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <div className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            <p className="text-amber-500">Total Fee</p>
            <p>(Bundler paid)</p>
          </div>

          <div className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">
            <span>{`(Base Fee Per Gas + maxPriorityFeePerGas) x gasUsed = `}</span>
            <span className="text-amber-500">{`${Ethers.formatEther(
              totalFee
            )} ETH`}</span>
          </div>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <button
            onClick={handleCreatePasskey}
            disabled={buttonDisabled}
            className="order-1 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Create Passkey
          </button>
          <button
            onClick={handleAddPasskeyToContract}
            disabled={buttonDisabled}
            className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Add Passkey
          </button>
          <button
            onClick={handleGetPasskey}
            disabled={buttonDisabled}
            className="order-2 w-1/4 m-auto p-3 border-0 rounded-lg text-base"
          >
            Get Passkey
          </button>
        </div>
        <div className="m-auto p-3 border-2 border-cyan-500 rounded-lg">
          <h2 className="text-2xl font-bold">Actual UserOp Gas Info</h2>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              Account deposit EntryPoint Balance
            </span>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${Ethers.formatEther(
              accountEthEntryPointBalance
            )} ETH`}</span>
            <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-red-500">{`(${Ethers.formatEther(
              accountEthEntryPointDiff
            )} ETH)`}</span>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <div className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              <p>UserOp: GasUsed</p>
              <p>
                (= Call Gas Used + Verification Gas Used + preVerificationGas)
              </p>
            </div>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${userOpGasUsed}`}</span>
            <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`100% x UserOp Total Fee`}</span>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-emerald-500">
              preVerificationGas
            </span>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${userOpPreVerificationGas}`}</span>
            <div className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              <span>{`${
                userOpGasUsed === BigInt("0")
                  ? 0
                  : (userOpPreVerificationGas * BigInt("100")) / userOpGasUsed
              }% x UserOp Total Fee = `}</span>
              <span className="text-emerald-500">{`${Ethers.formatEther(
                userOpGasUsed === BigInt("0")
                  ? 0
                  : (userOpPreVerificationGas * userOpTotalFee) / userOpGasUsed
              )} ETH`}</span>
            </div>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base text-amber-500">
              Call Gas Used + Verification Gas Used
            </span>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${
              userOpGasUsed - userOpPreVerificationGas
            }`}</span>
            <div className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              <span>{`${
                userOpGasUsed === BigInt("0")
                  ? 0
                  : ((userOpGasUsed - userOpPreVerificationGas) *
                      BigInt("100")) /
                    userOpGasUsed
              }% x UserOp Total Fee = `}</span>
              <span className="text-amber-500">{`${Ethers.formatEther(
                userOpGasUsed === BigInt("0")
                  ? 0
                  : ((userOpGasUsed - userOpPreVerificationGas) *
                      userOpTotalFee) /
                      userOpGasUsed
              )} ETH`}</span>
            </div>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              UserOp: Base Fee Per Gas
            </span>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${userOpBaseFeePerGas} Wei`}</span>
            <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`x userOpGasUsed = ${Ethers.formatEther(
              userOpGasUsed * userOpBaseFeePerGas
            )} ETH`}</span>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              UserOp: maxPriorityFeePerGas
            </span>
            <span className="order-2 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`${userOpMaxPriorityFeePerGas} Wei`}</span>
            <span className="order-3 w-2/6 m-auto p-3 border-0 rounded-lg text-base">{`x userOpGasUsed = ${Ethers.formatEther(
              userOpGasUsed * userOpMaxPriorityFeePerGas
            )} ETH`}</span>
          </div>
          <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
            <div className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
              <p>UserOp: Total Fee</p>
              <p>(Account paid (deposit EntryPoint))</p>
            </div>
            <div className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base">
              <span>{`(UserOp Base Fee Per Gas + UserOp maxPriorityFeePerGas) x gasUsed = `}</span>
              <span className="text-red-500">{`${Ethers.formatEther(
                userOpTotalFee
              )} ETH`}</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
