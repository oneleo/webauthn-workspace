import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";

import * as Ethers from "ethers";
import * as Webauthn from "@passwordless-id/webauthn";

import * as WebauthnBrowser from "@simplewebauthn/browser";
import * as WebauthnServer from "@simplewebauthn/server";
import * as WebauthnTypes from "@simplewebauthn/typescript-types";

// import { register } from "@passwordless-id/webauthn/dist/esm/client";

const PASSKEY_NAME = "irara";

interface LoggedInUser {
  id: string;
  username: string;
  devices: WebauthnTypes.AuthenticatorDevice[];
}

interface LoggedInFIDOUser extends LoggedInUser {
  currentAuthenticationUserVerification?: UserVerificationRequirement;
}

function App() {
  const [count, setCount] = useState(0);

  return (
    <>
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
    </>
  );
}

export default App;
