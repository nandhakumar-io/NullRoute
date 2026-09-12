import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import { ThemeProvider } from "./theme";
import { ToastProvider } from "./lib/toast";
import { ConfirmProvider } from "./lib/confirm";
import App from "./App";
import Login from "./pages/Login";
import { AuthProvider, ProtectedRoute } from "./context/AuthContext";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import Backups from "./pages/Backups";
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
import ReportVerification from "./pages/ReportVerfication";
import KnowledgeBase from "./pages/KnowledgeBase";
import Observability from "./pages/Observability";
import EvidenceLedger from "./pages/EvidenceLedger";
import Drift from "./pages/Drift";
import Schedules from "./pages/Schedules";
import Alerts from "./pages/Alerts";
import AiAnalysisOverview from "./pages/AiAnalysisOverview";
import AuditLog from "./pages/AuditLog";
import ConfigSearch from "./pages/ConfigSearch";
import NetworkScans from "./pages/NetworkScans";
import NetworkScanDetail from "./pages/NetworkScanDetail";
import SystemHealth from "./pages/SystemHealth";
import Gns3Integration from "./pages/Gns3Integration";
import ControlLibrary from "./pages/ControlLibrary";
import VulnerabilityDashboard from "./pages/VulnerabilityDashboard";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
    <AuthProvider>
    <ToastProvider>
    <ConfirmProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<ProtectedRoute><App /></ProtectedRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<Devices />} />
          <Route path="devices/:deviceId" element={<DeviceDetail />} />
          <Route path="backups" element={<Backups />} />
          <Route path="devices/:deviceId/compare" element={<SnapshotCompare />} />
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
          <Route path="report-verification" element={<ReportVerification />} />
          <Route path="knowledge-base" element={<KnowledgeBase />} />
          <Route path="system/health" element={<SystemHealth />} />
          <Route path="observability" element={<Observability />} />
          <Route path="evidence" element={<EvidenceLedger />} />
          <Route path="drift" element={<Drift />} />
          <Route path="schedules" element={<Schedules />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="ai-analysis" element={<AiAnalysisOverview />} />
          <Route path="audit-log" element={<AuditLog />} />
          <Route path="gns3-integration" element={<Gns3Integration />} />
          <Route path="control-library" element={<ControlLibrary />} />
          <Route path="vulnerabilities" element={<VulnerabilityDashboard />} />
        </Route>
      </Routes>
    </BrowserRouter>
    </ConfirmProvider>
    </ToastProvider>
    </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>
);