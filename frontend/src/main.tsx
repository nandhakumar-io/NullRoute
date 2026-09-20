import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import "./index.css";
import { ThemeProvider } from "./theme";
import { ToastProvider } from "./lib/toast";
import { ConfirmProvider } from "./lib/confirm";
import ErrorBoundary from "./components/ErrorBoundary";
import App from "./App";

function RouteErrorBoundary({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  return <ErrorBoundary key={location.pathname}>{children}</ErrorBoundary>;
}

// Per-page boundary, nested INSIDE the <App> layout route rather than
// wrapping the whole <Routes> tree. A page that throws during render used
// to take the entire shell down with it -- sidebar, header, everything --
// because the only ErrorBoundary sat above <App> itself, so React had
// nothing left to unmount but the whole tree. Any single page (say,
// DeviceDetail rendering bad data returned right after a scan) crashing
// no longer blanks navigation for the rest of the app; it shows the error
// card in the content pane and the sidebar stays usable to navigate away.
function PageErrorBoundary({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  return <ErrorBoundary key={location.pathname}>{children}</ErrorBoundary>;
}
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
import EventTriggers from "./pages/EventTriggers";
import Alerts from "./pages/Alerts";
import AIAnalysisOverview from "./pages/AIAnalysisOverview";
import AuditLog from "./pages/AuditLog";
import ConfigSearch from "./pages/ConfigSearch";
import NetworkScans from "./pages/NetworkScans";
import NetworkScanDetail from "./pages/NetworkScanDetail";
import SystemHealth from "./pages/SystemHealth";
import Gns3Integration from "./pages/Gns3Integration";
import ControlLibrary from "./pages/ControlLibrary";
import ControlDetail from "./pages/ControlDetail";
import VulnerabilityDashboard from "./pages/VulnerabilityDashboard";
import FindingDetail from "./pages/FindingDetail";
import ReviewQueue from "./pages/ChangeRequest";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
    <AuthProvider>
    <ToastProvider>
    <ConfirmProvider>
    <BrowserRouter>
      <RouteErrorBoundary>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<ProtectedRoute><App /></ProtectedRoute>}>
          <Route index element={<PageErrorBoundary><Dashboard /></PageErrorBoundary>} />
          <Route path="devices" element={<PageErrorBoundary><Devices /></PageErrorBoundary>} />
          <Route path="devices/:deviceId" element={<PageErrorBoundary><DeviceDetail /></PageErrorBoundary>} />
          <Route path="backups" element={<PageErrorBoundary><Backups /></PageErrorBoundary>} />
          <Route path="devices/:deviceId/compare" element={<PageErrorBoundary><SnapshotCompare /></PageErrorBoundary>} />
          <Route path="discovery" element={<PageErrorBoundary><NetworkScans initialTab="discovery" /></PageErrorBoundary>} />
          <Route path="network-scans" element={<PageErrorBoundary><NetworkScans /></PageErrorBoundary>} />
          <Route path="network-scans/:scanJobId" element={<PageErrorBoundary><NetworkScanDetail /></PageErrorBoundary>} />
          <Route path="config-search" element={<PageErrorBoundary><ConfigSearch /></PageErrorBoundary>} />
          <Route path="topology" element={<PageErrorBoundary><Topology /></PageErrorBoundary>} />
          <Route path="ingestion" element={<PageErrorBoundary><Ingestion /></PageErrorBoundary>} />
          <Route path="scans/:scanId" element={<PageErrorBoundary><ScanDetail /></PageErrorBoundary>} />
          <Route path="scans/:scanId/batfish" element={<PageErrorBoundary><BatfishAnalysis /></PageErrorBoundary>} />
          <Route path="scans/:scanId/opa" element={<PageErrorBoundary><PolicyEvaluation /></PageErrorBoundary>} />
          <Route path="validation" element={<PageErrorBoundary><Validation /></PageErrorBoundary>} />
          <Route path="compliance" element={<PageErrorBoundary><Compliance /></PageErrorBoundary>} />
          <Route path="findings/:findingId" element={<PageErrorBoundary><FindingDetail /></PageErrorBoundary>} />
          <Route path="training" element={<PageErrorBoundary><TrainingCenter /></PageErrorBoundary>} />
          <Route path="reports" element={<PageErrorBoundary><Reports /></PageErrorBoundary>} />
          <Route path="report-verification" element={<PageErrorBoundary><ReportVerification /></PageErrorBoundary>} />
          <Route path="knowledge-base" element={<PageErrorBoundary><KnowledgeBase /></PageErrorBoundary>} />
          <Route path="system/health" element={<PageErrorBoundary><SystemHealth /></PageErrorBoundary>} />
          <Route path="observability" element={<PageErrorBoundary><Observability /></PageErrorBoundary>} />
          <Route path="evidence" element={<PageErrorBoundary><EvidenceLedger /></PageErrorBoundary>} />
          <Route path="drift" element={<PageErrorBoundary><Drift /></PageErrorBoundary>} />
          <Route path="schedules" element={<PageErrorBoundary><Schedules /></PageErrorBoundary>} />
          <Route path="event-triggers" element={<PageErrorBoundary><EventTriggers /></PageErrorBoundary>} />
          <Route path="alerts" element={<PageErrorBoundary><Alerts /></PageErrorBoundary>} />
          <Route path="review-queue" element={<PageErrorBoundary><ReviewQueue /></PageErrorBoundary>} />
          <Route path="ai-analysis" element={<PageErrorBoundary><AIAnalysisOverview /></PageErrorBoundary>} />
          <Route path="audit-log" element={<PageErrorBoundary><AuditLog /></PageErrorBoundary>} />
          <Route path="gns3-integration" element={<PageErrorBoundary><Gns3Integration /></PageErrorBoundary>} />
          <Route path="control-library" element={<PageErrorBoundary><ControlLibrary /></PageErrorBoundary>} />
          <Route path="control-library/:controlId" element={<PageErrorBoundary><ControlDetail /></PageErrorBoundary>} />
          <Route path="vulnerabilities" element={<PageErrorBoundary><VulnerabilityDashboard /></PageErrorBoundary>} />
        </Route>
      </Routes>
      </RouteErrorBoundary>
    </BrowserRouter>
    </ConfirmProvider>
    </ToastProvider>
    </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>
);