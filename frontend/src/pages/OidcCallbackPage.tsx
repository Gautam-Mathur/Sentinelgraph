import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner } from "../components/Badges";

export const OidcCallbackPage: React.FC = () => {
  const { completeOidcLogin, isAuthenticated } = useAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  const [statusText, setStatusText] = useState("Completing Enterprise SSO authentication...");
  const processedRef = useRef(false);

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/overview", { replace: true });
      return;
    }
    if (processedRef.current) return;
    processedRef.current = true;

    const idpError = searchParams.get("error");
    const idpErrorDesc = searchParams.get("error_description");
    if (idpError) {
      setError(new Error(idpErrorDesc ? `${idpError}: ${idpErrorDesc}` : idpError));
      setStatusText("Enterprise SSO authentication returned an error.");
      return;
    }

    const code = searchParams.get("code");
    const state = searchParams.get("state");
    if (!code || !state) {
      setError(new Error("Missing required OIDC 'code' or 'state' query parameters."));
      setStatusText("Invalid OIDC callback parameters.");
      return;
    }

    const savedTenantSlug = sessionStorage.getItem("sentinelgraph.oidc_tenant_slug") || undefined;
    sessionStorage.removeItem("sentinelgraph.oidc_tenant_slug");

    completeOidcLogin(code, state, savedTenantSlug)
      .then(() => {
        navigate("/overview", { replace: true });
      })
      .catch((err) => {
        setError(err);
        setStatusText("Failed to exchange OIDC authorization code.");
      });
  }, [completeOidcLogin, isAuthenticated, navigate, searchParams]);

  return (
    <main className="login-shell" id="main-content" tabIndex={-1}>
      <div className="login-card">
        <h1 style={{ marginTop: 0, fontSize: "1.4rem" }}>Enterprise SSO Callback</h1>
        <p role="status" style={{ color: "var(--text-secondary)" }}>
          {statusText}
        </p>
        <ErrorBanner error={error} />
        <div className="btn-row" style={{ marginBlockStart: "1rem" }}>
          <Link to="/login" className="btn btn-secondary">
            Return to Sign In
          </Link>
        </div>
      </div>
    </main>
  );
};
