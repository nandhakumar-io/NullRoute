import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import { ThemeProvider } from "./theme";
import App from "./App";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import SnapshotCompare from "./pages/SnapshotCompare";
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
import AuditLog from "./pages/AuditLog";
import ConfigSearch from "./pages/ConfigSearch";
import NetworkScans from "./pages/NetworkScans";
import NetworkScanDetail from "./pages/NetworkScanDetail";
import SystemHealth from "./pages/SystemHealth";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<Devices />} />
          <Route path="devices/:deviceId" element={<DeviceDetail />} />
          <Route path="devices/:deviceId/compare" element={<SnapshotCompare />} />
          {/* Discovery (ad-hoc nmap probe) and Network Scans (orchestrated
              discovery+collection+compliance jobs) are now one page with
              tabs -- /discovery redirects into the merged page. */}
          <Route path="discovery" element={<NetworkScans initialTab="discovery" />} />
          <Route path="network-scans" element={<NetworkScans />} />
          <Route path="network-scans/:scanJobId" element={<NetworkScanDetail />} />
          <Route path="config-search" element={<ConfigSearch />} />
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
          <Route path="system/health" element={<SystemHealth />} />
          <Route path="observability" element={<Observability />} />
          <Route path="evidence" element={<EvidenceLedger />} />
          <Route path="drift" element={<Drift />} />
          <Route path="schedules" element={<Schedules />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="ai-analysis" element={<AIAnalysisOverview />} />
          <Route path="audit-log" element={<AuditLog />} />
        </Route>
      </Routes>
    </BrowserRouter>
    </ThemeProvider>
  </React.StrictMode>
);