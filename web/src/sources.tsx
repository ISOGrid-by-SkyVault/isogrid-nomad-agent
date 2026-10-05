import { useEffect, useRef, useState, type FormEvent } from "react";
import { del, get, post, put, when } from "./api";

type Connection = { name: string; kind: "github" | "gitlab" | "registry"; host: string; username?: string; created_at: string; created_by?: string };
type Build = {
  id: string;
  connection: string;
  repository: string;
  ref: string;
  commit?: string;
  image: string;
  digest?: string;
  status: "running" | "succeeded" | "failed";
  error?: string;
  started_at: string;
  finished_at?: string;
};

const KIND = {
  github: {
    label: "GitHub",
    host: "github.com",
    secret: "Token",
    help: "A fine-grained personal access token limited to the repositories ISOGrid may build, with read access to Contents and Metadata. For GitHub Enterprise, give its host.",
  },
  gitlab: {
    label: "GitLab",
    host: "gitlab.com",
    secret: "Token",
    help: "A personal, group or project access token with the read_api and read_repository scopes. For a self-managed GitLab, give its host.",
  },
  registry: {
    label: "Container registry",
    host: "",
    secret: "Password or token",
    help: "A robot account or access token. Read is enough to deploy images; add write to push the images the agent builds. Use docker.io for Docker Hub.",
  },
} as const;

function useList<T>(path: string, every = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = () =>
    get<T>(path)
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  useEffect(() => {
    void refresh();
    if (!every) return;
    const timer = setInterval(() => void refresh(), every);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, every]);
  return { data, error, refresh };
}

export function ConnectionsPage() {
  const { data, error, refresh } = useList<{ vault: boolean; connections: Connection[] }>("/api/connections");
  const [kind, setKind] = useState<Connection["kind"]>("github");
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [tests, setTests] = useState<Record<string, { ok: boolean; message: string } | "running">>({});

  const reset = () => {
    setName("");
    setHost("");
    setUsername("");
    setSecret("");
    setEditing(false);
  };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNote(null);
    try {
      const saved = await put<Connection>("/api/connections", { name, kind, host, username, secret });
      setNote({ ok: true, text: `Saved ${saved.name}. Its credential is in your Vault and will not be shown again.` });
      reset();
      await refresh();
      void test(saved.name);
    } catch (e) {
      setNote({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const test = async (target: string) => {
    setTests((t) => ({ ...t, [target]: "running" }));
    try {
      const out = await post<{ ok: boolean; message: string }>("/api/connections/test", { name: target });
      setTests((t) => ({ ...t, [target]: out }));
    } catch (e) {
      setTests((t) => ({ ...t, [target]: { ok: false, message: (e as Error).message } }));
    }
  };
  const remove = async (target: string) => {
    if (!window.confirm(`Delete the connection ${target} and its credential? Applications that build or pull through it will fail at their next deploy.`)) return;
    try {
      await del(`/api/connections?name=${encodeURIComponent(target)}`);
      setNote({ ok: true, text: `Deleted ${target}.` });
      await refresh();
    } catch (e) {
      setNote({ ok: false, text: (e as Error).message });
    }
  };
  const edit = (c: Connection) => {
    setKind(c.kind);
    setName(c.name);
    setHost(c.host);
    setUsername(c.username ?? "");
    setSecret("");
    setEditing(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const meta = KIND[kind];
  return (
    <>
      <h1>Connections</h1>
      <p className="lead">
        Where this agent fetches code and images: your GitHub, your GitLab, your registries. The credentials are typed here and kept in your Vault. ISOGrid learns each connection's name and host, asks the agent
        questions through it, and never holds a token.
      </p>
      {error && <div className="card error">{error}</div>}
      {data && !data.vault && <p className="empty">No Vault is configured for this agent, and connections keep their credentials there. Re-run the installer with your Vault or OpenBao address.</p>}
      {data?.vault && (
        <form className="panel form" onSubmit={save}>
          <strong>{editing ? `Change ${name}` : "Add a connection"}</strong>
          <div className="segmented" role="group" aria-label="Kind">
            {(Object.keys(KIND) as Connection["kind"][]).map((k) => (
              <button type="button" key={k} className={k === kind ? "active" : ""} disabled={editing} onClick={() => setKind(k)}>
                {KIND[k].label}
              </button>
            ))}
          </div>
          <span className="hint">{meta.help}</span>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "registry" ? "main-registry" : `${kind}-main`} disabled={editing} autoComplete="off" spellCheck={false} required />
          </label>
          <label>
            Host
            <input value={host} onChange={(e) => setHost(e.target.value)} placeholder={meta.host || "registry.example.com"} autoComplete="off" spellCheck={false} required={kind === "registry"} />
          </label>
          {kind === "registry" && (
            <label>
              Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" spellCheck={false} />
            </label>
          )}
          <label>
            {meta.secret}
            <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" placeholder={editing ? "leave empty to keep the stored one" : ""} required={!editing} />
          </label>
          <div className="actions">
            <button className="primary" disabled={busy}>
              {busy ? "Saving…" : editing ? "Save changes" : "Add connection"}
            </button>
            {editing && (
              <button type="button" onClick={reset}>
                Cancel
              </button>
            )}
          </div>
        </form>
      )}
      {note && <p className={note.ok ? "note ok" : "note bad"}>{note.text}</p>}
      {data && data.connections.length === 0 && data.vault && <p className="empty">No connection yet.</p>}
      {data?.connections.map((c) => {
        const result = tests[c.name];
        return (
          <section className="panel" key={c.name}>
            <header className="panel-head">
              <div>
                <strong>{c.name}</strong>
                <div className="hint">
                  {KIND[c.kind].label} · <span className="mono">{c.host}</span>
                  {c.username ? ` · ${c.username}` : ""}
                </div>
              </div>
              <div className="actions">
                <button onClick={() => void test(c.name)} disabled={result === "running"}>
                  {result === "running" ? "Testing…" : "Test"}
                </button>
                <button onClick={() => edit(c)}>Change</button>
                <button className="danger" onClick={() => void remove(c.name)}>
                  Delete
                </button>
              </div>
            </header>
            {result && result !== "running" && <p className={`hint ${result.ok ? "" : "reason"}`}>{result.ok ? "✓ " : "✗ "}{result.message}</p>}
            <p className="hint">
              Added {when(c.created_at)}
              {c.created_by ? ` by ${c.created_by}` : ""}.
            </p>
          </section>
        );
      })}
    </>
  );
}

const BUILD_TONE = { running: "warn", succeeded: "good", failed: "bad" } as const;

export function BuildsPage() {
  const { data, error } = useList<{ builds: Build[] }>("/api/builds", 5000);
  const [open, setOpen] = useState<string | null>(null);
  const [log, setLog] = useState<{ log: string; truncated: boolean } | null>(null);
  const box = useRef<HTMLPreElement>(null);
  const current = data?.builds.find((b) => b.id === open);

  useEffect(() => {
    if (!open) return;
    let live = true;
    const load = () =>
      get<{ log: string; truncated: boolean }>(`/api/builds/${open}/log`)
        .then((out) => live && setLog(out))
        .catch(() => undefined);
    setLog(null);
    void load();
    const timer = setInterval(() => {
      if (current?.status === "running") void load();
    }, 3000);
    return () => {
      live = false;
      clearInterval(timer);
    };
    // Reload once more when the build leaves "running", to get its last lines.
  }, [open, current?.status]);
  useEffect(() => {
    if (box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [log]);

  return (
    <>
      <h1>Builds</h1>
      <p className="lead">
        Images this agent built for ISOGrid: source fetched from your code host, built by the Docker engine here, pushed to your registry. ISOGrid is told the commit, the image and whether it worked. The output
        below stays on this machine.
      </p>
      {error && <div className="card error">{error}</div>}
      {data && data.builds.length === 0 && <p className="empty">No build yet. They start when an application built from a repository is deployed to this cluster.</p>}
      {data?.builds.map((b) => (
        <section className="panel" key={b.id}>
          <header className="panel-head">
            <div>
              <strong>{b.repository}</strong> <span className="hint">at {b.ref}</span>
              <div className="hint mono">{b.image}</div>
            </div>
            <div className="panel-meta">
              <span className={`badge ${BUILD_TONE[b.status]}`}>{b.status}</span>
              <button onClick={() => setOpen(open === b.id ? null : b.id)}>{open === b.id ? "Hide output" : "Output"}</button>
            </div>
          </header>
          {b.error && <p className="hint reason">{b.error}</p>}
          <p className="hint">
            {b.commit ? `Commit ${b.commit.slice(0, 12)} · ` : ""}
            through {b.connection} · started {when(b.started_at)}
            {b.finished_at ? ` · took ${Math.max(1, Math.round((Date.parse(b.finished_at) - Date.parse(b.started_at)) / 1000))}s` : ""}
            {b.digest ? ` · ${b.digest.slice(0, 19)}…` : ""}
          </p>
          {open === b.id && (
            <pre className="logbox short" ref={box} tabIndex={0}>
              {log ? (log.truncated ? "[earlier output not shown]\n" : "") + (log.log || "No output yet.") : "Loading…"}
            </pre>
          )}
        </section>
      ))}
    </>
  );
}
