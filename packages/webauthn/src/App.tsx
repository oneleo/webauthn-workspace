import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";

import * as Ethers5 from "ethers";
import * as BananaPasskeyManager from "@rize-labs/banana-passkey-manager";

const PASSKEY_NAME = "<irara>";

function App() {
  const [count, setCount] = useState(0);
  const [balance, setBalance] = useState<Ethers5.BigNumber>(
    Ethers5.BigNumber.from(0)
  );

  const handleCreatePasskey = async () => {
    const passkeyProvider = new Ethers5.providers.JsonRpcProvider(
      import.meta.env.VITE_PROVIDER
    );
    const passkeyInstance = new BananaPasskeyManager.BananaPasskeyEoaSigner(
      passkeyProvider
    );
    await passkeyInstance.init(PASSKEY_NAME);
    setBalance(await passkeyInstance.getBalance());
  };

  return (
    <>
      <div>
        <a href="https://vitejs.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
      <div>
        <button onClick={handleCreatePasskey}>Passkey Test</button>
      </div>
      <div>
        <span>{`${import.meta.env.VITE_PROVIDER}`}</span>
      </div>
      <div>
        <span>{`${balance}`}</span>
      </div>
    </>
  );
}

export default App;
