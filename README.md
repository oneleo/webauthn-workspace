# webauthn-workspace

- Initial and setup project name

```
% pnpm install
% PKG1="contracts" && PKG2="webauthn"
```

- Setup environment variables

```
% cp package/${PKG1}/.env.example package/${PKG1}/.env
% code package/${PKG1}/.env

% cp package/${PKG2}/.env.example package/${PKG2}/.env
% code package/${PKG2}/.env
```

- Start Hardhat node

```
% PKG1="contracts" && pnpm --filter ${PKG1} start:aa
```

- Start React node

```
% pnpm copy:typechain
% PKG2="webauthn" && pnpm --filter ${PKG2} dev
```

- Onchain passkey verify contract sample:
  - [https://sepolia.etherscan.io/address/0x433f0e4f5f8a31084f36c0fccf9ad29aad2ec34f#readContract](https://sepolia.etherscan.io/address/0x433f0e4f5f8a31084f36c0fccf9ad29aad2ec34f#readContract)
