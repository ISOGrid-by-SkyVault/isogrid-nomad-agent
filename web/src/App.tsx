import { useEffect, useState } from "react";

type Health = {
  status: string;
  version: string;
  mode: "attached" | "detached";
  uptime: string;
};

// The sections the operator frontend will have. Each one is served by the
// agent itself and reads only local state: nothing here reaches ISOGrid.
const SECTIONS = [
  { id: "overview", label: "Overview", ready: true },
  { id: "deployments", label: "Deployments", ready: false },
  { id: "secrets", label: "Secrets", ready: false },
  { id: "logs", label: "Logs", ready: false },
  { id: "metrics", label: "Performance", ready: false },
  { id: "approvals", label: "Approvals", ready: false },
  { id: "settings", label: "Settings", ready: false },
] as const;

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<(typeof SECTIONS)[number]["id"]>("overview");

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetch("/api/healthz")
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
        .then((h: Health) => {
          if (!cancelled) {
            setHealth(h);
            setError(null);
          }
        })
        .catch((e: Error) => {
          if (!cancelled) setError(e.message);
        });
    load();
    const timer = setInterval(load, 10_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>ISOGrid Nomad</span>
        </div>
        <nav>
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              className={s.id === section ? "active" : ""}
              disabled={!s.ready}
              onClick={() => setSection(s.id)}
              title={s.ready ? undefined : "Not built yet"}
            >
              {s.label}
            </button>
          ))}
        </nav>
        <p className="rail-note">This console is served by the agent on your network. ISOGrid cannot reach it.</p>
      </aside>
      <main>
        <h1>Overview</h1>
        {error && <div className="card error">The agent did not answer: {error}</div>}
        {health && (
          <div className="cards">
            <div className="card">
              <span className="label">Status</span>
              <span className="value">{health.status}</span>
            </div>
            <div className="card">
              <span className="label">Mode</span>
              <span className="value">{health.mode}</span>
              <span className="hint">
                {health.mode === "attached"
                  ? "Connected to the ISOGrid broker over mutual TLS."
                  : "No broker configured: the agent only serves this console."}
              </span>
            </div>
            <div className="card">
              <span className="label">Version</span>
              <span className="value">{health.version}</span>
            </div>
            <div className="card">
              <span className="label">Uptime</span>
              <span className="value">{health.uptime}</span>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
