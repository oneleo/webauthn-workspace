import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

import * as WebauthnLocal from "./components/WebauthnLocal";
import * as WebauthnOnchain from "./components/WebauthnOnchain";
import * as WebauthnOnchainAllInOne from "./components/WebauthnOnchainAllInOne.tsx";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WebauthnLocal.WebauthnLocal />
    <WebauthnOnchainAllInOne.WebauthnOnchainAllInOne />
    <WebauthnOnchain.WebauthnOnchain />
    <App />
  </React.StrictMode>
);
