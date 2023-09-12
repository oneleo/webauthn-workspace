import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

import * as WebauthnLocal from "./components/01-WebauthnLocal.tsx";
import * as WebauthnCreateGetHardhat from "./components/03-WebauthnCreateGetHardhat.tsx";
import * as WebauthnHardhat from "./components/02-WebauthnHardhat.tsx";
import * as WebauthnHardhatAccountAbstraction from "./components/04-WebauthnHardhatAccountAbstraction.tsx";
import * as WebauthnOnchainAccountAbstraction from "./components/05-WebauthnOnchainAccountAbstraction.tsx";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
    <WebauthnLocal.WebauthnLocal />
    <WebauthnHardhat.WebauthnHardhat />
    <WebauthnCreateGetHardhat.WebauthnCreateGetHardhat />
    <WebauthnHardhatAccountAbstraction.WebauthnHardhatAccountAbstraction />
    {/* <WebauthnOnchainAccountAbstraction.WebauthnOnchainAccountAbstraction /> */}
  </React.StrictMode>
);
