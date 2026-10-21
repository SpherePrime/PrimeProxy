import React from "react";
import ReactDOM from "react-dom/client";
import { DnsPage } from "./components/DnsPage";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <DnsPage />
  </React.StrictMode>,
);
