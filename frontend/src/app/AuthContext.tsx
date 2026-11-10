import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { apiRequest, registerRefreshHandler, registerSessionProvider } from "../lib/api";
import type {
  LoginResponse,
  MembershipSummary,
  RoleName,
  TenantInfo,
  UserProfile,
} from "../types/api";

interface StoredSession {
  token: string;
  refreshToken?: string | null;
  user: UserProfile;
  activeTenant: TenantInfo;
  memberships: MembershipSummary[];
}

interface AuthContextValue {
  token: string | null;
  user: UserProfile | null;
  activeTenant: TenantInfo | null;
  memberships: MembershipSummary[];
  isAuthenticated: boolean;
  login: (email: string, password: string, tenantSlug?: string) => Promise<void>;
  completeOidcLogin: (code: string, state: string, tenantSlug?: string) => Promise<void>;
  switchTenant: (tenantId: string) => Promise<void>;
  refreshMe: () => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (...roles: RoleName[]) => boolean;
}

const STORAGE_KEY = "sentinelgraph.session.v1";

function loadStored(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredSession;
  } catch {
    return null;
  }
}

let currentSession: StoredSession | null = loadStored();

function syncSessionProvider(next: StoredSession | null): void {
  currentSession = next;
  registerSessionProvider(() => ({
    token: currentSession?.token ?? null,
    tenantId: currentSession?.activeTenant?.id ?? null,
  }));
}

syncSessionProvider(currentSession);

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<StoredSession | null>(() => loadStored());

  useEffect(() => {
    syncSessionProvider(session);
  }, [session]);

  const persist = useCallback((next: StoredSession | null) => {
    syncSessionProvider(next);
    setSession(next);
    if (next) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  useEffect(() => {
    registerRefreshHandler(async () => {
      const rt = currentSession?.refreshToken;
      if (!rt) return false;
      try {
        const refreshed = await apiRequest<LoginResponse>("/auth/refresh", {
          method: "POST",
          body: { refresh_token: rt },
        });
        const next: StoredSession = {
          token: refreshed.access_token,
          refreshToken: refreshed.refresh_token ?? rt,
          user: refreshed.user,
          activeTenant: refreshed.active_tenant,
          memberships: refreshed.memberships,
        };
        persist(next);
        return true;
      } catch {
        persist(null);
        return false;
      }
    });
    return () => registerRefreshHandler(null);
  }, [persist]);

  const login = useCallback(
    async (email: string, password: string, tenantSlug?: string) => {
      const data = await apiRequest<LoginResponse>("/auth/login", {
        method: "POST",
        body: { email, password, tenant_slug: tenantSlug || null },
      });
      const next: StoredSession = {
        token: data.access_token,
        refreshToken: data.refresh_token ?? null,
        user: data.user,
        activeTenant: data.active_tenant,
        memberships: data.memberships,
      };
      registerSessionProvider(() => ({
        token: next.token,
        tenantId: next.activeTenant.id,
      }));
      persist(next);
    },
    [persist]
  );

  const completeOidcLogin = useCallback(
    async (code: string, state: string, tenantSlug?: string) => {
      const data = await apiRequest<LoginResponse>("/auth/oidc/callback", {
        method: "POST",
        body: { code, state, tenant_slug: tenantSlug || null },
      });
      const next: StoredSession = {
        token: data.access_token,
        refreshToken: data.refresh_token ?? null,
        user: data.user,
        activeTenant: data.active_tenant,
        memberships: data.memberships,
      };
      registerSessionProvider(() => ({
        token: next.token,
        tenantId: next.activeTenant.id,
      }));
      persist(next);
    },
    [persist]
  );

  const refreshMe = useCallback(async () => {
    if (!session) return;
    const me = await apiRequest<{
      user: UserProfile;
      active_tenant: TenantInfo;
      memberships: MembershipSummary[];
    }>("/auth/me");
    persist({
      token: session.token,
      refreshToken: session.refreshToken ?? null,
      user: me.user,
      activeTenant: me.active_tenant,
      memberships: me.memberships,
    });
  }, [persist, session]);

  const switchTenant = useCallback(
    async (tenantId: string) => {
      if (!session) return;
      const res = await apiRequest<{
        access_token: string;
        refresh_token?: string;
        active_tenant: TenantInfo;
      }>("/auth/switch-tenant", {
        method: "POST",
        body: { tenant_id: tenantId },
      });
      registerSessionProvider(() => ({
        token: res.access_token,
        tenantId: res.active_tenant.id,
      }));
      const me = await apiRequest<{
        user: UserProfile;
        active_tenant: TenantInfo;
        memberships: MembershipSummary[];
      }>("/auth/me");
      persist({
        token: res.access_token,
        refreshToken: res.refresh_token ?? session.refreshToken ?? null,
        user: me.user,
        activeTenant: me.active_tenant,
        memberships: me.memberships,
      });
    },
    [persist, session]
  );

  const logout = useCallback(async () => {
    const activeToken = currentSession?.token;
    const refreshToken = currentSession?.refreshToken ?? null;
    if (activeToken) {
      try {
        await apiRequest("/auth/logout", {
          method: "POST",
          body: { refresh_token: refreshToken },
        });
      } catch {
        // Proceed with local session teardown even if server token already expired
      }
    }
    registerSessionProvider(() => ({ token: null, tenantId: null }));
    persist(null);
  }, [persist]);

  const hasRole = useCallback(
    (...roles: RoleName[]) => {
      if (!session) return false;
      return roles.includes(session.activeTenant.role);
    },
    [session]
  );

  return (
    <AuthContext.Provider
      value={{
        token: session?.token ?? null,
        user: session?.user ?? null,
        activeTenant: session?.activeTenant ?? null,
        memberships: session?.memberships ?? [],
        isAuthenticated: Boolean(session?.token),
        login,
        completeOidcLogin,
        switchTenant,
        refreshMe,
        logout,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
