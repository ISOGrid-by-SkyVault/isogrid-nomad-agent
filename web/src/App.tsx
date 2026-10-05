import { useEffect, useState } from "react";

type StreamStatus = {
  state: "connecting" | "connected" | "refused" | "disconnected";
  since: string;
  reason?: string;
  attempts: number;
  next_attempt_at?: string;
  heartbeat_seconds?: number;
  intents_received: number;
  replies_sent: number;
  last_intent_at?: string;
  certificate_cn?: string;
  certificate_not_after: string;
};

type Health = {
  status: string;
  version: string;
  mode: "attached" | "detached";
  uptime: string;
  cluster_id?: string;
  organization_id?: string;
  stream?: StreamStatus;
  capabilities?: string[];
  intents?: { executed: number; refused: number };
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

const STREAM_WORDS: Record<StreamStatus["state"], string> = {
  connecting: "Connecting to ISOGrid.",
  connected: "Connected to ISOGrid. Intents arrive on this channel, replies and heartbeats go back on it.",
  refused: "ISOGrid refused the connection. Fix the cause, the agent keeps retrying.",
  disconnected: "The channel dropped. The agent reconnects by itself.",
};

function when(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

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
    const timer = setInterval(load, 5_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const stream = health?.stream;

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
                  ? "An outbound WebSocket to the ISOGrid API, authenticated with the cluster's certificate."
                  : "No stream configured: the agent only serves this console."}
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
            {stream && (
              <>
                <div className={`card stream ${stream.state}`}>
                  <span className="label">ISOGrid channel</span>
                  <span className="value">{stream.state}</span>
                  <span className="hint">{STREAM_WORDS[stream.state]}</span>
                  {stream.reason && <span className="hint reason">{stream.reason}</span>}
                  <span className="hint">
                    Since {when(stream.since)}
                    {stream.next_attempt_at ? ` · next attempt ${when(stream.next_attempt_at)}` : ""}
                    {stream.heartbeat_seconds ? ` · heartbeat every ${stream.heartbeat_seconds}s` : ""}
                    {` · attempt ${stream.attempts}`}
                  </span>
                </div>
                <div className="card">
                  <span className="label">Identity</span>
                  <span className="value small">{stream.certificate_cn}</span>
                  <span className="hint">
                    Certificate valid until {when(stream.certificate_not_after)}.
                    {health.organization_id ? ` Organization ${health.organization_id}.` : ""}
                  </span>
                </div>
                <div className="card">
                  <span className="label">Intents</span>
                  <span className="value">
                    {stream.intents_received} received · {stream.replies_sent} answered
                  </span>
                  <span className="hint">
                    {health.intents ? `${health.intents.executed} executed, ${health.intents.refused} refused.` : ""}
                    {stream.last_intent_at ? ` Last one ${when(stream.last_intent_at)}.` : " None yet."}
                  </span>
                  {health.capabilities && (
                    <span className="hint">This agent executes: {health.capabilities.join(", ")}.</span>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
