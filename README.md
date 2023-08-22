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
% pnpm --filter ${PKG1} start:aa
```

- Start React node

```
% pnpm --filter ${PKG2} dev
```
