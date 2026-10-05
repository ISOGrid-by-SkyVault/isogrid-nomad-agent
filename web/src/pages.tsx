import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ApiError,
  del,
  get,
  post,
  put,
  when,
  type Intent,
  type LogLine,
  type Metrics,
  type Overview,
  type Secrets,
  type Service,
  type Settings,
} from "./api";
import { Chart } from "./Chart";

/** Loads on mount and every `every` ms; keeps the last good answer on error. */
function useLoad<T>(load: () => Promise<T>, every: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loader = useRef(load);
  loader.current = load;
  const refresh = useCallback(() => {
    return loader
      .current()
      .then((value) => {
        setData(value);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(() => {
    setData(null);
    void refresh();
    if (!every) return;
    const timer = setInterval(() => void refresh(), every);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, refresh };
}

function Problem({ children }: { children: ReactNode }) {
  return <div className="card error">{children}</div>;
}

function Badge({ tone, children }: { tone: "good" | "warn" | "bad" | "muted"; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

const STATE_TONE: Record<Service["state"], "good" | "warn" | "bad" | "muted"> = {
  running: "good",
  starting: "warn",
  degraded: "warn",
  failed: "bad",
  stopped: "muted",
};

// -- Overview -------------------------------------------------------------------------

const STREAM_WORDS = {
  connecting: "Connecting to ISOGrid.",
  connected: "Connected. Intents arrive on this channel; replies and heartbeats go back on it.",
  refused: "ISOGrid refused the connection. Fix the cause; the agent keeps retrying.",
  disconnected: "The channel dropped. The agent reconnects by itself.",
} as const;

export function OverviewPage() {
  const { data, error } = useLoad(() => get<Overview>("/api/overview"), 5000);
  const stream = data?.stream;
  return (
    <>
      <h1>Overview</h1>
      {error && <Problem>The agent did not answer: {error}</Problem>}
      {data && (
        <div className="cards">
          <div className="card">
            <span className="label">Agent</span>
            <span className="value">{data.version}</span>
            <span className="hint">
              {data.mode === "attached" ? "Attached to ISOGrid" : "Detached: console only"} · up {data.uptime}
            </span>
          </div>
          <div className="card">
            <span className="label">Docker engine</span>
            <span className="value">{data.engine.ok ? data.engine.name : "unreachable"}</span>
            <span className={`hint ${data.engine.ok ? "" : "reason"}`}>
              {data.engine.ok
                ? `Docker ${data.engine.version} · Swarm ${data.engine.swarm} · ${data.engine.manager ? "manager" : "worker"} · ${data.engine.nodes} node${data.engine.nodes === 1 ? "" : "s"}`
                : data.engine.error}
            </span>
          </div>
          <div className="card">
            <span className="label">Vault</span>
            <span className="value">
              {!data.vault ? "not configured" : data.vault.logged_in ? "ready" : data.vault.sealed ? "sealed" : data.vault.reachable ? "not signed in" : "unreachable"}
            </span>
            <span className={`hint ${data.vault && !data.vault.logged_in ? "reason" : ""}`}>
              {!data.vault
                ? "Secrets by reference need a Vault or OpenBao; re-run the installer to set one."
                : data.vault.logged_in
                  ? `Version ${data.vault.version}. The agent can read and write below its prefix.`
                  : data.vault.error}
            </span>
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
                <span className="hint">Certificate valid until {when(stream.certificate_not_after)}.</span>
                <span className="hint">Organization {data.organization_id}.</span>
              </div>
              <div className="card">
                <span className="label">Intents since start</span>
                <span className="value">
                  {data.intents?.executed ?? 0} executed · {data.intents?.refused ?? 0} refused
                </span>
                <span className="hint">{stream.last_intent_at ? `Last one ${when(stream.last_intent_at)}.` : "None yet."}</span>
                {data.capabilities && <span className="hint">Executes: {data.capabilities.join(", ")}.</span>}
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}

// -- Deployments ----------------------------------------------------------------------

export function DeploymentsPage({ openLogs }: { openLogs: (service: string) => void }) {
  const { data, error } = useLoad(() => get<{ services: Service[] }>("/api/services"), 5000);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <h1>Deployments</h1>
      <p className="lead">
        The services ISOGrid deployed on this Swarm through the agent. Anything else running here is yours and the agent leaves it alone.
      </p>
      {error && <Problem>{error}</Problem>}
      {data && data.services.length === 0 && <p className="empty">Nothing deployed yet. Deploy an application to this cluster from the ISOGrid console.</p>}
      {data?.services.map((s) => (
        <section className="panel" key={s.service_id}>
          <header className="panel-head">
            <div>
              <strong>{s.name}</strong>
              <div className="hint mono">{s.image}</div>
            </div>
            <div className="panel-meta">
              <Badge tone={STATE_TONE[s.state]}>{s.state}</Badge>
              <span className="hint">
                {s.running} of {s.desired} running
              </span>
            </div>
          </header>
          {s.message && <p className="hint reason">{s.message}</p>}
          <p className="hint">
            {s.ports.length
              ? s.ports.map((p) => `port ${p.published} → ${p.target}/${p.protocol} (${p.mode})`).join(" · ")
              : "No published port: reachable on its overlay network only."}
          </p>
          <div className="actions">
            <button onClick={() => setOpen(open === s.name ? null : s.name)}>{open === s.name ? "Hide tasks" : `Tasks (${s.tasks.length})`}</button>
            <button onClick={() => openLogs(s.name)}>Logs</button>
          </div>
          {open === s.name && (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Task</th>
                    <th>State</th>
                    <th>Wanted</th>
                    <th>Since</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {s.tasks.map((t) => (
                    <tr key={t.id}>
                      <td className="mono">
                        {t.slot}.{t.id.slice(0, 8)}
                      </td>
                      <td>{t.state}</td>
                      <td>{t.desired}</td>
                      <td>{when(t.at)}</td>
                      <td className="reason">{t.error}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ))}
    </>
  );
}

// -- Logs -----------------------------------------------------------------------------

export function LogsPage({ service, setService }: { service: string; setService: (s: string) => void }) {
  const services = useLoad(() => get<{ services: Service[] }>("/api/services"), 15000);
  const [tail, setTail] = useState(200);
  const [follow, setFollow] = useState(true);
  const names = services.data?.services.map((s) => s.name) ?? [];
  const current = service || names[0] || "";
  const logs = useLoad(
    () => (current ? get<{ lines: LogLine[] }>(`/api/services/${encodeURIComponent(current)}/logs?tail=${tail}`) : Promise.resolve({ lines: [] })),
    follow ? 4000 : 0,
    [current, tail, follow],
  );
  const box = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [logs.data, follow]);
  return (
    <>
      <h1>Logs</h1>
      <p className="lead">Read from the Docker engine on this machine when you open this page. They are not sent to ISOGrid.</p>
      <div className="toolbar">
        <label>
          Service
          <select value={current} onChange={(e) => setService(e.target.value)}>
            {names.length === 0 && <option value="">no managed service</option>}
            {names.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label>
          Lines
          <select value={tail} onChange={(e) => setTail(Number(e.target.value))}>
            {[100, 200, 500, 1000, 2000].map((n) => (
              <option key={n} value={n}>
                last {n}
              </option>
            ))}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> Follow
        </label>
        <button onClick={() => void logs.refresh()}>Refresh</button>
      </div>
      {logs.error && <Problem>{logs.error}</Problem>}
      <pre className="logbox" ref={box} tabIndex={0}>
        {logs.data?.lines.length
          ? logs.data.lines.map((l, i) => (
              <div key={i} className={l.stream === "stderr" ? "stderr" : undefined}>
                <span className="logtime">{l.time ? l.time.slice(11, 23) : ""}</span> {l.text}
              </div>
            ))
          : current
            ? "No output in the lines the engine kept."
            : "Deploy an application to this cluster to see its output here."}
      </pre>
    </>
  );
}

// -- Performance ----------------------------------------------------------------------

const RANGES = [
  { minutes: 15, label: "15 min" },
  { minutes: 60, label: "1 hour" },
  { minutes: 360, label: "6 hours" },
  { minutes: 1440, label: "24 hours" },
  { minutes: 10080, label: "7 days" },
];

const cores = (milli: number) => (milli >= 1000 ? `${(milli / 1000).toFixed(2)} cores` : `${Math.round(milli)} mCPU`);
const bytes = (b: number) => (b >= 1 << 30 ? `${(b / (1 << 30)).toFixed(2)} GiB` : `${Math.round(b / (1 << 20))} MiB`);

export function PerformancePage() {
  const [minutes, setMinutes] = useState(60);
  const { data, error } = useLoad(() => get<Metrics>(`/api/metrics?minutes=${minutes}`), 15000, [minutes]);
  const to = Math.floor(Date.now() / 1000);
  const from = to - minutes * 60;
  return (
    <>
      <h1>Performance</h1>
      <p className="lead">
        CPU and memory of each managed service on this node
        {data ? `, sampled every ${data.sample_seconds}s and kept ${Math.round(data.retention_seconds / 86400)} days` : ""}. Stored here, not sent anywhere.
      </p>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r.minutes} className={r.minutes === minutes ? "active" : ""} onClick={() => setMinutes(r.minutes)}>
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {error && <Problem>{error}</Problem>}
      {data && data.services.length === 0 && <p className="empty">No samples in this range yet. They start with the first managed service.</p>}
      {data?.services.map((s) => {
        const last = s.points[s.points.length - 1];
        const limit = last && last.limit > 0 && last.limit < 1 << 40 ? last.limit : 0;
        return (
          <section className="panel" key={s.name}>
            <header className="panel-head">
              <strong>{s.name}</strong>
              <span className="hint">{last ? `${last.n} container${last.n === 1 ? "" : "s"}` : ""}</span>
            </header>
            <div className="charts">
              <Chart title="CPU" from={from} to={to} format={cores} points={s.points.map((p) => ({ t: p.t, v: p.cpu }))} />
              <Chart
                title="Memory"
                from={from}
                to={to}
                format={bytes}
                points={s.points.map((p) => ({ t: p.t, v: p.mem }))}
                ceiling={limit ? { value: limit, label: `limit ${bytes(limit)}` } : undefined}
              />
            </div>
            <details>
              <summary>Readings as a table</summary>
              <div className="table-scroll short">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>CPU</th>
                      <th>Memory</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.points
                      .slice(-60)
                      .reverse()
                      .map((p) => (
                        <tr key={p.t}>
                          <td>{new Date(p.t * 1000).toLocaleString()}</td>
                          <td>{cores(p.cpu)}</td>
                          <td>{bytes(p.mem)}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </details>
          </section>
        );
      })}
    </>
  );
}

// -- Activity -------------------------------------------------------------------------

const INTENT_TONE: Record<string, "good" | "warn" | "bad" | "muted"> = { ok: "good", error: "bad", rejected: "bad", unsupported: "warn" };

export function ActivityPage() {
  const [all, setAll] = useState(false);
  const { data, error } = useLoad(() => get<{ attached: boolean; intents: Intent[] }>(`/api/activity${all ? "?all=1" : ""}`), 5000, [all]);
  return (
    <>
      <h1>Activity</h1>
      <p className="lead">
        Every intent ISOGrid sent this agent and how it ended. Each one is signed, checked and executed at most once; this journal is what enforces that across restarts.
      </p>
      <div className="toolbar">
        <label className="check">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Include routine reads (status, ping, networks)
        </label>
      </div>
      {error && <Problem>{error}</Problem>}
      {data && !data.attached && <p className="empty">This agent runs detached, so ISOGrid sends it nothing.</p>}
      {data && data.attached && data.intents.length === 0 && <p className="empty">Nothing yet.</p>}
      {data && data.intents.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Intent</th>
                <th>About</th>
                <th>Outcome</th>
                <th>Took</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.intents.map((i) => (
                <tr key={i.id}>
                  <td>{when(i.received_at)}</td>
                  <td className="mono">{i.kind || "unreadable"}</td>
                  <td>{i.subject}</td>
                  <td>
                    <Badge tone={INTENT_TONE[i.status] ?? "muted"}>{i.status}</Badge>
                  </td>
                  <td>{i.duration_ms >= 1000 ? `${(i.duration_ms / 1000).toFixed(1)} s` : `${i.duration_ms} ms`}</td>
                  <td className="reason">{i.error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

// -- Secrets --------------------------------------------------------------------------

export function SecretsPage() {
  const { data, error, refresh } = useLoad(() => get<Secrets>("/api/secrets"), 0);
  const [ref, setRef] = useState("");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNote(null);
    try {
      const out = await put<{ ref: string }>("/api/secrets", { ref, value });
      setNote({ ok: true, text: `Stored ${out.ref}. The value will not be shown again.` });
      setRef("");
      setValue("");
      await refresh();
    } catch (e) {
      setNote({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const remove = async (target: string) => {
    if (!window.confirm(`Delete ${target} and all its versions from your Vault? Applications that reference it will fail at their next deploy.`)) return;
    try {
      await del(`/api/secrets?ref=${encodeURIComponent(target)}`);
      setNote({ ok: true, text: `Deleted ${target}.` });
      await refresh();
    } catch (e) {
      setNote({ ok: false, text: (e as Error).message });
    }
  };

  const ready = data?.health?.logged_in;
  return (
    <>
      <h1>Secrets</h1>
      <p className="lead">
        Values are typed here and stored in your own Vault. ISOGrid only ever learns the reference, such as <span className="mono">apps/billing/DATABASE_URL</span>; the agent reads the value at deploy time and hands it to the container.
      </p>
      {error && <Problem>{error}</Problem>}
      {data && !data.configured && (
        <p className="empty">No Vault is configured for this agent. Re-run the installer and give it your Vault or OpenBao address and an AppRole.</p>
      )}
      {data?.configured && data.vault && (
        <section className="panel">
          <header className="panel-head">
            <div>
              <strong>{data.vault.address}</strong>
              <div className="hint mono">
                {data.vault.mount}/{data.vault.prefix}/… · {data.vault.method}
              </div>
            </div>
            <Badge tone={ready ? "good" : "bad"}>{ready ? "ready" : data.health?.sealed ? "sealed" : "unavailable"}</Badge>
          </header>
          {!ready && <p className="hint reason">{data.health?.error}</p>}
          {data.error && <p className="hint reason">{data.error}</p>}
        </section>
      )}
      {ready && (
        <>
          <form className="panel form" onSubmit={save}>
            <strong>Set a secret</strong>
            <label>
              Reference
              <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="apps/billing/DATABASE_URL" autoComplete="off" spellCheck={false} required />
            </label>
            <label>
              Value
              <textarea value={value} onChange={(e) => setValue(e.target.value)} rows={3} autoComplete="off" spellCheck={false} required />
            </label>
            <span className="hint">Writing to an existing reference stores a new version. Up to eight segments of letters, digits, dots, dashes and underscores.</span>
            <div className="actions">
              <button className="primary" disabled={busy}>
                {busy ? "Storing…" : "Store in Vault"}
              </button>
            </div>
          </form>
          {note && <p className={note.ok ? "note ok" : "note bad"}>{note.text}</p>}
          <section className="panel">
            <strong>References ({data?.refs.length ?? 0})</strong>
            {data?.truncated && <p className="hint">Showing the first 500.</p>}
            {data?.refs.length === 0 && <p className="hint">None yet.</p>}
            <ul className="refs">
              {data?.refs.map((r) => (
                <li key={r}>
                  <span className="mono">{r}</span>
                  <span className="actions">
                    <button onClick={() => setRef(r)}>Replace</button>
                    <button className="danger" onClick={() => void remove(r)}>
                      Delete
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </>
  );
}

// -- Settings -------------------------------------------------------------------------

const AGENT_LABELS: Record<string, string> = {
  version: "Version",
  listen: "Console listens on",
  data_dir: "Data directory",
  docker_host: "Docker engine",
  stream_url: "ISOGrid stream",
  cluster_id: "Cluster",
  organization_id: "Organization",
  sample_interval: "Sample interval",
  sample_retention: "Sample retention",
  session_lifetime: "Session lifetime",
};

export function SettingsPage({ onAccountChange }: { onAccountChange: () => void }) {
  const { data, error, refresh } = useLoad(() => get<Settings>("/api/settings"), 0);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [enrol, setEnrol] = useState<{ secret: string; uri: string } | null>(null);
  const [totpPassword, setTotpPassword] = useState("");
  const [code, setCode] = useState("");

  const run = async (action: () => Promise<string>) => {
    setNote(null);
    try {
      setNote({ ok: true, text: await action() });
      await refresh();
      onAccountChange();
    } catch (e) {
      setNote({ ok: false, text: e instanceof ApiError ? e.message : String(e) });
    }
  };

  return (
    <>
      <h1>Settings</h1>
      {error && <Problem>{error}</Problem>}
      {note && <p className={note.ok ? "note ok" : "note bad"}>{note.text}</p>}
      {data && (
        <>
          <form
            className="panel form"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await post("/api/account/password", { current, new: next });
                setCurrent("");
                setNext("");
                return "Password changed. Your other sessions were signed out.";
              });
            }}
          >
            <strong>Password of {data.account.username}</strong>
            <label>
              Current password
              <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
            </label>
            <label>
              New password
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" minLength={Number(data.agent.password_min_size)} required />
            </label>
            <span className="hint">At least {data.agent.password_min_size} characters.</span>
            <div className="actions">
              <button className="primary">Change password</button>
            </div>
          </form>

          <section className="panel form">
            <strong>Second factor</strong>
            {data.account.totp_enabled ? (
              <form
                className="form"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    await post("/api/account/totp/disable", { password: totpPassword, code });
                    setTotpPassword("");
                    setCode("");
                    return "Second factor turned off.";
                  });
                }}
              >
                <span className="hint">On: signing in asks for a code from your authenticator app.</span>
                <label>
                  Password
                  <input type="password" value={totpPassword} onChange={(e) => setTotpPassword(e.target.value)} autoComplete="current-password" required />
                </label>
                <label>
                  Current code
                  <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
                </label>
                <div className="actions">
                  <button className="danger">Turn off</button>
                </div>
              </form>
            ) : enrol ? (
              <form
                className="form"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    await post("/api/account/totp/confirm", { code });
                    setEnrol(null);
                    setCode("");
                    return "Second factor turned on.";
                  });
                }}
              >
                <span className="hint">Add this key to an authenticator app (time-based, six digits), then type the code it shows.</span>
                <code className="secret-key">{enrol.secret.replace(/(.{4})/g, "$1 ").trim()}</code>
                <span className="hint mono wrap">{enrol.uri}</span>
                <label>
                  Code
                  <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
                </label>
                <div className="actions">
                  <button className="primary">Confirm</button>
                </div>
              </form>
            ) : (
              <form
                className="form"
                onSubmit={(e) => {
                  e.preventDefault();
                  setNote(null);
                  post<{ secret: string; uri: string }>("/api/account/totp/begin", { password: totpPassword })
                    .then((out) => {
                      setEnrol(out);
                      setTotpPassword("");
                    })
                    .catch((err: Error) => setNote({ ok: false, text: err.message }));
                }}
              >
                <span className="hint">Off. Turn it on so a stolen password is not enough to open this console.</span>
                <label>
                  Password
                  <input type="password" value={totpPassword} onChange={(e) => setTotpPassword(e.target.value)} autoComplete="current-password" required />
                </label>
                <div className="actions">
                  <button className="primary">Set up</button>
                </div>
              </form>
            )}
          </section>

          <section className="panel">
            <strong>This agent</strong>
            <p className="hint">Set by the installer. Re-run it on the manager to change any of these.</p>
            <dl className="facts">
              {Object.entries(AGENT_LABELS).map(([key, label]) =>
                data.agent[key] ? (
                  <div key={key}>
                    <dt>{label}</dt>
                    <dd className="mono">{String(data.agent[key])}</dd>
                  </div>
                ) : null,
              )}
              {data.vault && (
                <div>
                  <dt>Vault</dt>
                  <dd className="mono">
                    {data.vault.address} · {data.vault.mount}/{data.vault.prefix} · {data.vault.method}
                  </dd>
                </div>
              )}
            </dl>
          </section>
        </>
      )}
    </>
  );
}
