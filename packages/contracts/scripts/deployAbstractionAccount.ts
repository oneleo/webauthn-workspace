import * as Hardhat from "hardhat";
// Contract interface:
// https://docs.ethers.org/v6/api/contract/
import * as Ethers from "ethers";
import * as Addresses from "./addresses";

// Import contract ABIs.
import {
  abi as abiEntryPoint,
  bytecode as byteEntryPoint,
} from "@account-abstraction/contracts/artifacts/EntryPoint.json";

import {
  abi as abiPaymaster,
  bytecode as bytePaymaster,
} from "@account-abstraction/contracts/artifacts/DepositPaymaster.json";

// import {
//   abi as abiAccountFactory,
//   bytecode as byteAccountFactory,
// } from "@account-abstraction/contracts/artifacts/SimpleAccountFactory.json";

import {
  abi as abiAccountFactory,
  bytecode as byteAccountFactory,
} from "../artifacts/contracts/core/PasskeyManagerFactory.sol/PassKeyManagerFactory.json";

import {
  abi as abiUniswapSwapRouter,
  bytecode as byteSwapRouter,
} from "@uniswap/v3-periphery/artifacts/contracts/SwapRouter.sol/SwapRouter.json";

// Import contract Types.
import * as typesFactoryEntryPoint from "../typechain-types/factories/@account-abstraction/contracts/core/EntryPoint__factory";

import * as typesFactoryPaymaster from "../typechain-types/factories/@account-abstraction/contracts/samples/DepositPaymaster__factory";

// import * as TypesFactoryAccountFactory from "../typechain-types/factories/@account-abstraction/contracts/samples/SimpleAccountFactory__factory";

import * as typesFactoryAccountFactory from "../typechain-types/factories/contracts/core/PasskeyManagerFactory.sol/PassKeyManagerFactory__factory";

// import * as TypesFactoryAccount from "../typechain-types/factories/@account-abstraction/contracts/samples/SimpleAccount__factory";

import * as typesFactoryAccount from "../typechain-types/factories/contracts/core/PasskeyManager__factory";

const DEBUG = false;

const SALT = BigInt(336699);
const PROXY_DATA = String("0x");

// Get the Hatdhat network name and provider.
const NETWORK_NAME = Hardhat.network.name;

async function main() {
  const signers = await Hardhat.ethers.getSigners();
  const provider = Hardhat.ethers.provider;
  const feeData = await provider.getFeeData();
  const block = await provider.getBlock("latest");
  const blockTimeStamp = block ? block.timestamp : 0;

  const [
    accountOwner,
    bundlerOwner,
    erc1967ProxyOwner,
    accountFactoryOwner,
    paymasterOwner,
    entryPointOwner,
  ] = signers;

  // Declare the gas overrides argument.
  // The gasLimit should be sufficiently large to avoid the
  // "Error: Transaction reverted: trying to deploy a contract whose code is too large" error.
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

  // Deploy the EntryPoint contract on localhost.
  const entryPointContractAddress = (
    await deploy(abiEntryPoint, byteEntryPoint, entryPointOwner, gasOverrides)
  ).target.toString();

  // const entryPointContract = await Hardhat.ethers.getContractAt(
  //   "EntryPoint",
  //   entryPointContractAddress
  // );

  const entryPointContract = typesFactoryEntryPoint.EntryPoint__factory.connect(
    entryPointContractAddress,
    provider
  );

  // Deploy the Paymaster contract on localhost.
  const paymasterContractAddress = (
    await deploy(
      abiPaymaster,
      bytePaymaster,
      paymasterOwner,
      entryPointContractAddress,
      gasOverrides
    )
  ).target.toString();

  // const paymasterContract = await Hardhat.ethers.getContractAt(
  //   "DepositPaymaster",
  //   paymasterContractAddress
  // );

  const paymasterContract =
    typesFactoryPaymaster.DepositPaymaster__factory.connect(
      paymasterContractAddress,
      provider
    );

  // Deploy the AccountFactory contract on localhost.
  const accountFactoryContractAddress = (
    await deploy(
      abiAccountFactory,
      byteAccountFactory,
      accountFactoryOwner,
      entryPointContractAddress,
      gasOverrides
    )
  ).target.toString();

  const accountFactoryContract =
    typesFactoryAccountFactory.PassKeyManagerFactory__factory.connect(
      accountFactoryContractAddress,
      provider
    );

  // Deposit ether(s) from the Paymaster contract to the EntryPoint.
  // https://github.com/ethers-io/ethers.js/issues/4287
  let writeTransaction: Ethers.TransactionResponse = await paymasterContract
    .connect(paymasterOwner)
    .deposit(gasOverridesWithValue);

  let readContract: any = await entryPointContract.deposits(
    paymasterContractAddress
  );

  log("depositsAmountFromPaymaster", readContract);

  // Display contract addresses.
  log("entryPoint address", entryPointContract.target);
  log("paymaster address", paymasterContract.target);
  log("accountFactory address", accountFactoryContract.target);
}

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

const deploy = async (
  abi: Ethers.Interface | Ethers.InterfaceAbi,
  bytecode: Ethers.BytesLike | { object: string },
  runner: null | Ethers.ContractRunner,
  ...args: Ethers.ethers.ContractMethodArgs<any[]>
) => {
  return await (
    await new Ethers.ContractFactory(abi, bytecode, runner).deploy(...args)
  ).waitForDeployment();
};

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
