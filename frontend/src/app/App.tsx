import React, { useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./AuthContext";
import { AppLayout } from "../components/AppLayout";
import { AssessmentsPage } from "../pages/AssessmentsPage";
import { AssetsPage } from "../pages/AssetsPage";
import { AttackPathsPage } from "../pages/AttackPathsPage";
import { AuditLogPage } from "../pages/AuditLogPage";
import { FindingsPage } from "../pages/FindingsPage";
import { IdentitiesPage } from "../pages/IdentitiesPage";
import { ImportsPage } from "../pages/ImportsPage";
import { IntegrationsPage } from "../pages/IntegrationsPage";
import { JobsPage } from "../pages/JobsPage";
import { LoginPage } from "../pages/LoginPage";
import { OidcCallbackPage } from "../pages/OidcCallbackPage";
import { OverviewPage } from "../pages/OverviewPage";
import { PathDetailPage } from "../pages/PathDetailPage";
import { RelationshipsPage } from "../pages/RelationshipsPage";
import { RemediationPage } from "../pages/RemediationPage";
import { ReportsPage } from "../pages/ReportsPage";
import { SettingsPage } from "../pages/SettingsPage";

const ROUTE_TITLES: Record<string, string> = {
  "/login": "Sign In | SentinelGraph",
  "/auth/callback": "SSO Callback | SentinelGraph",
  "/overview": "Overview Dashboard | SentinelGraph",
  "/assessments": "Assessments & Graph | SentinelGraph",
  "/paths": "Attack Paths | SentinelGraph",
  "/remediations": "Remediation Planner | SentinelGraph",
  "/assets": "Assets & Services | SentinelGraph",
  "/findings": "Findings & Triage | SentinelGraph",
  "/identities": "Identities & Groups | SentinelGraph",
  "/relationships": "Relationships | SentinelGraph",
  "/imports": "Imports (Staged) | SentinelGraph",
  "/integrations": "Connectors | SentinelGraph",
  "/reports": "Reports | SentinelGraph",
  "/jobs": "Background Jobs | SentinelGraph",
  "/audit": "Audit Log | SentinelGraph",
  "/settings": "Settings & Privacy | SentinelGraph",
};

const DocumentTitleSync: React.FC = () => {
  const { pathname } = useLocation();
  useEffect(() => {
    const matched = Object.entries(ROUTE_TITLES).find(([prefix]) => pathname.startsWith(prefix));
    document.title = matched ? matched[1] : "SentinelGraph — Enterprise Attack-Path Intelligence";
  }, [pathname]);
  return null;
};

const ProtectedShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <AppLayout>{children}</AppLayout>;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <DocumentTitleSync />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/auth/callback" element={<OidcCallbackPage />} />
        <Route
          path="/overview"
          element={
            <ProtectedShell>
              <OverviewPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/assets"
          element={
            <ProtectedShell>
              <AssetsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/findings"
          element={
            <ProtectedShell>
              <FindingsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/identities"
          element={
            <ProtectedShell>
              <IdentitiesPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/relationships"
          element={
            <ProtectedShell>
              <RelationshipsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/assessments"
          element={
            <ProtectedShell>
              <AssessmentsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/paths"
          element={
            <ProtectedShell>
              <AttackPathsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/paths/:pathId"
          element={
            <ProtectedShell>
              <PathDetailPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/remediations"
          element={
            <ProtectedShell>
              <RemediationPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/imports"
          element={
            <ProtectedShell>
              <ImportsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/integrations"
          element={
            <ProtectedShell>
              <IntegrationsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/reports"
          element={
            <ProtectedShell>
              <ReportsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/jobs"
          element={
            <ProtectedShell>
              <JobsPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/audit"
          element={
            <ProtectedShell>
              <AuditLogPage />
            </ProtectedShell>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedShell>
              <SettingsPage />
            </ProtectedShell>
          }
        />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AuthProvider>
  );
};

export default App;
