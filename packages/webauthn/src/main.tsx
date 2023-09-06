import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

import * as WebauthnLocal from "./components/WebauthnLocal";
import * as WebauthnOnchain from "./components/WebauthnOnchain";
import * as WebauthnOnchainAllInOne from "./components/WebauthnOnchainAllInOne.tsx";
import * as WebauthnAccountAbstraction from "./components/WebauthnAccountAbstraction";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WebauthnLocal.WebauthnLocal />
    <WebauthnOnchainAllInOne.WebauthnOnchainAllInOne />
    <WebauthnOnchain.WebauthnOnchain />
    <WebauthnAccountAbstraction.WebauthnAccountAbstraction />
    <App />
  </React.StrictMode>
);
