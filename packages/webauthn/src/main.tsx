import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

import * as WebauthnApp from "./Webauthn.tsx";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WebauthnApp.WebauthnApp />
    <App />
  </React.StrictMode>
);
