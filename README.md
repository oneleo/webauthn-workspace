# webauthn-workspace

## Step 1. Prepare projects' packages

```
% git clone https://github.com/oneleo/webauthn-workspace.git
% cd webauthn-workspace/

% git checkout verify_passkey_contract
% pnpm install
```

## Step 2. Setup Hardhat environment variables and start project

- Setup environment variables

```
% PKG1="contracts"
% cp packages/${PKG1}/.env.example packages/${PKG1}/.env

% code packages/${PKG1}/.env
```

- Start Hardhat node

```
% PKG1="contracts" && pnpm --filter ${PKG1} start:aa
```

## Step 3. Setup React environment variables and start project

- Open another Terminal
- Setup environment variables

```
% PKG2="webauthn"
% cp packages/${PKG2}/.env.example packages/${PKG2}/.env
% code packages/${PKG2}/.env
```

- Start React node

```
% PKG2="webauthn" && pnpm --filter ${PKG2} typechain
% PKG2="webauthn" && pnpm --filter ${PKG2} dev
```

- Open website
  - [http://localhost:5173/](http://localhost:5173/)

## Recourses

- Simple WebAuthN
  - [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn)
- Banana Wallet - Passkey contract
  - [passkey-contracts](https://github.com/Banana-Wallet/passkey-contracts)
- Banana Wallet - Passkey EOA
  - [banana-passkey-eoa](https://github.com/Banana-Wallet/banana-passkey-eoa)
- Passkey verify contract sample:
  - [0x433f0e4f5f8a31084f36c0fccf9ad29aad2ec34f](https://sepolia.etherscan.io/address/0x433f0e4f5f8a31084f36c0fccf9ad29aad2ec34f#readContract) on Sepolia testnet
- Passkey account abstraction contract sample:
  - [0x405a1f2C4F725f13bCBd2e22fda0460D4E693fBc](https://sepolia.etherscan.io/address/0x405a1f2C4F725f13bCBd2e22fda0460D4E693fBc) on Sepolia testnet
