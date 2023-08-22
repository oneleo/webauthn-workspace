import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";

const MNEMONIC = {
  mnemonic:
    process.env.MNEMONIC ||
    "test test test test test test test test test test test junk",
};
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || "";
const ALCHEMY_MAINNET = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;
const ALCHEMY_SEPOLIA = `https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;
const ALCHEMY_GOERLI = `https://eth-goerli.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;

const FORK_CHAIN: string = "mainnet";
const FORK_CHAIN_ID =
  FORK_CHAIN === "mainnet"
    ? 1337
    : FORK_CHAIN === "sepolia"
    ? 11155111
    : FORK_CHAIN === "goerli"
    ? 5
    : 1337;
const FORK_CHAIN_URL =
  FORK_CHAIN === "mainnet"
    ? ALCHEMY_MAINNET
    : FORK_CHAIN === "sepolia"
    ? ALCHEMY_SEPOLIA
    : FORK_CHAIN === "goerli"
    ? ALCHEMY_GOERLI
    : ALCHEMY_MAINNET;
const FORK_CHAIN_BLOCK =
  FORK_CHAIN === "mainnet"
    ? 17888888
    : FORK_CHAIN === "sepolia"
    ? 4111111
    : FORK_CHAIN === "goerli"
    ? 9533333
    : 17888888;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 10000,
      },
    },
  },

  networks: {
    mainnet: {
      url: ALCHEMY_MAINNET,
      chainId: 1,
      accounts: MNEMONIC,
    },
    sepolia: {
      url: ALCHEMY_SEPOLIA,
      chainId: 11155111,
      accounts: MNEMONIC,
    },
    goerli: {
      url: ALCHEMY_GOERLI,
      chainId: 5,
      accounts: MNEMONIC,
    },
    // Running Hardhat node with the following settings.
    hardhat: {
      chainId: FORK_CHAIN_ID,
      accounts: MNEMONIC,
      forking: {
        url: FORK_CHAIN_URL,
        blockNumber: FORK_CHAIN_BLOCK,
      },
    },
    localhost: {
      url: `http://127.0.0.1:8545`,
      chainId: FORK_CHAIN_ID,
      accounts: MNEMONIC,
    },
  },
  etherscan: {
    apiKey: `${ETHERSCAN_API_KEY}`,
  },
};

export default config;
