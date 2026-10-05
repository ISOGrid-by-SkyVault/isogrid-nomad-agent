import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ApiError, get, post, type Session } from "./api";
import { BuildsPage, ConnectionsPage } from "./sources";
import { ActivityPage, DeploymentsPage, LogsPage, OverviewPage, PerformancePage, SecretsPage, SettingsPage } from "./pages";

// Each section is served by the agent itself and reads only local state:
// the engine, the agent's own store, your Vault. Nothing here reaches ISOGrid.
const SECTIONS = [
  { id: "overview", label: "Overview" },
  { id: "deployments", label: "Deployments" },
  { id: "builds", label: "Builds" },
  { id: "connections", label: "Connections" },
  { id: "secrets", label: "Secrets" },
  { id: "logs", label: "Logs" },
  { id: "performance", label: "Performance" },
  { id: "activity", label: "Activity" },
  { id: "settings", label: "Settings" },
] as const;
type SectionId = (typeof SECTIONS)[number]["id"];

function sectionFromHash(): SectionId {
  const id = window.location.hash.replace("#", "");
  return (SECTIONS.find((s) => s.id === id)?.id ?? "overview") as SectionId;
}

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark" aria-hidden="true" />
      <span>ISOGrid Nomad</span>
    </div>
  );
}

function Gate({ session, onDone }: { session: Session; onDone: () => void }) {
  const setup = session.setup_required;
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (setup) await post("/api/setup", { token, username, password });
      else await post("/api/login", { username, password, code });
      onDone();
    } catch (e) {
      if (e instanceof ApiError && e.code === "totp_required") setNeedCode(true);
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="gate">
      <form className="panel form gate-card" onSubmit={submit}>
        <Brand />
        <h1>{setup ? "Create the operator account" : "Sign in"}</h1>
        {setup && (
          <>
            <p className="hint">
              This console has no account yet. The agent printed a setup token in its log so that reaching this page is not enough to claim it:
            </p>
            <code className="secret-key">docker service logs isogrid-nomad-agent 2&gt;&amp;1 | grep "setup token"</code>
            <label>
              Setup token
              <input value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false} required />
            </label>
          </>
        )}
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={setup ? "new-password" : "current-password"}
            minLength={setup ? 12 : undefined}
            required
          />
        </label>
        {setup && <span className="hint">At least 12 characters. You can add a second factor in Settings afterwards.</span>}
        {needCode && (
          <label>
            Code from your authenticator app
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" autoFocus required />
          </label>
        )}
        {error && <p className="note bad">{error}</p>}
        <div className="actions">
          <button className="primary" disabled={busy}>
            {busy ? "One moment…" : setup ? "Create the account" : "Sign in"}
          </button>
        </div>
        <p className="rail-note">This console is served by the agent on your network. ISOGrid cannot reach it.</p>
      </form>
    </div>
  );
}

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<SectionId>(sectionFromHash);
  const [logService, setLogService] = useState("");

  const loadSession = useCallback(() => {
    get<Session>("/api/session")
      .then((s) => {
        setSession(s);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    loadSession();
    // A session that expired while the page was open sends the operator back
    // to the sign-in form instead of leaving every panel in error.
    const timer = setInterval(loadSession, 60_000);
    const onHash = () => setSection(sectionFromHash());
    window.addEventListener("hashchange", onHash);
    return () => {
      clearInterval(timer);
      window.removeEventListener("hashchange", onHash);
    };
  }, [loadSession]);

  const go = (id: SectionId) => {
    window.location.hash = id;
    setSection(id);
  };

  if (!session) {
    return <div className="gate">{error ? <div className="card error">The agent did not answer: {error}</div> : <p className="hint">Loading…</p>}</div>;
  }
  if (!session.authenticated) {
    return <Gate session={session} onDone={loadSession} />;
  }

  return (
    <div className="shell">
      <aside className="rail">
        <Brand />
        <nav aria-label="Sections">
          {SECTIONS.map((s) => (
            <button key={s.id} className={s.id === section ? "active" : ""} aria-current={s.id === section ? "page" : undefined} onClick={() => go(s.id)}>
              {s.label}
            </button>
          ))}
        </nav>
        <div className="rail-foot">
          <span className="hint">
            Signed in as <strong>{session.username}</strong>
          </span>
          <button
            onClick={() => {
              void post("/api/logout").finally(loadSession);
            }}
          >
            Sign out
          </button>
          <p className="rail-note">This console is served by the agent on your network. ISOGrid cannot reach it.</p>
        </div>
      </aside>
      <main>
        {section === "overview" && <OverviewPage />}
        {section === "deployments" && (
          <DeploymentsPage
            openLogs={(name) => {
              setLogService(name);
              go("logs");
            }}
          />
        )}
        {section === "builds" && <BuildsPage />}
        {section === "connections" && <ConnectionsPage />}
        {section === "secrets" && <SecretsPage />}
        {section === "logs" && <LogsPage service={logService} setService={setLogService} />}
        {section === "performance" && <PerformancePage />}
        {section === "activity" && <ActivityPage />}
        {section === "settings" && <SettingsPage onAccountChange={loadSession} />}
      </main>
    </div>
  );
}
