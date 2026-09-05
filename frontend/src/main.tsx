import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import App from "./App";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import Topology from "./pages/Topology";
import Ingestion from "./pages/Ingestion";
import ScanDetail from "./pages/ScanDetail";
import BatfishAnalysis from "./pages/BatfishAnalysis";
import PolicyEvaluation from "./pages/PolicyEvaluation";
import Validation from "./pages/Validation";
import Compliance from "./pages/Compliance";
import TrainingCenter from "./pages/TrainingCenter";
import Reports from "./pages/Reports";
import KnowledgeBase from "./pages/KnowledgeBase";
import Observability from "./pages/Observability";
import EvidenceLedger from "./pages/EvidenceLedger";
import Drift from "./pages/Drift";
import Schedules from "./pages/Schedules";
import Alerts from "./pages/Alerts";
import AIAnalysisOverview from "./pages/AIAnalysisOverview";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<Devices />} />
          <Route path="devices/:deviceId" element={<DeviceDetail />} />
          <Route path="topology" element={<Topology />} />
          <Route path="ingestion" element={<Ingestion />} />
          <Route path="scans/:scanId" element={<ScanDetail />} />
          <Route path="scans/:scanId/batfish" element={<BatfishAnalysis />} />
          <Route path="scans/:scanId/opa" element={<PolicyEvaluation />} />
          <Route path="validation" element={<Validation />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="training" element={<TrainingCenter />} />
          <Route path="reports" element={<Reports />} />
          <Route path="knowledge-base" element={<KnowledgeBase />} />
          <Route path="observability" element={<Observability />} />
          <Route path="evidence" element={<EvidenceLedger />} />
          <Route path="drift" element={<Drift />} />
          <Route path="schedules" element={<Schedules />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="ai-analysis" element={<AIAnalysisOverview />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);