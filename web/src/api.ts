// Everything the console asks its own agent. Nothing here reaches ISOGrid.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: {
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        // Required on every change; a page on another site cannot send it.
        ...(method !== "GET" ? { "X-ISOGrid-Console": "1" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "unreachable", "The agent did not answer. Is it running?");
  }
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    /* an empty or non-JSON body */
  }
  if (!response.ok) {
    const err = (data ?? {}) as { code?: string; error?: string };
    throw new ApiError(response.status, err.code ?? "error", err.error ?? `HTTP ${response.status}`);
  }
  return data as T;
}

export const get = <T>(path: string) => request<T>("GET", path);
export const post = <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {});
export const put = <T>(path: string, body: unknown) => request<T>("PUT", path, body);
export const del = <T>(path: string) => request<T>("DELETE", path);

export type Session = {
  setup_required: boolean;
  authenticated: boolean;
  username?: string;
  totp_enabled?: boolean;
  version: string;
};

export type StreamStatus = {
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

export type VaultHealth = {
  reachable: boolean;
  initialized: boolean;
  sealed: boolean;
  version?: string;
  logged_in: boolean;
  error?: string;
};

export type Overview = {
  status: string;
  version: string;
  mode: "attached" | "detached";
  uptime: string;
  engine: { ok: boolean; error?: string; name?: string; version?: string; swarm?: string; manager?: boolean; nodes?: number };
  vault?: VaultHealth;
  cluster_id?: string;
  organization_id?: string;
  stream?: StreamStatus;
  capabilities?: string[];
  intents?: { executed: number; refused: number };
};

export type Port = { published: number; target: number; protocol: string; mode: string };
export type Task = { id: string; slot: number; node: string; desired: string; state: string; error?: string; image: string; at: string };
export type Service = {
  service_id: string;
  name: string;
  image: string;
  desired: number;
  running: number;
  state: "running" | "starting" | "degraded" | "failed" | "stopped";
  message?: string;
  update_state?: string;
  ports: Port[];
  tasks: Task[];
  updated_at: string;
};

export type LogLine = { time: string; stream: "stdout" | "stderr"; text: string };

export type Point = { t: number; cpu: number; mem: number; limit: number; n: number };
export type Metrics = {
  minutes: number;
  bucket_seconds: number;
  sample_seconds: number;
  retention_seconds: number;
  services: { name: string; points: Point[] }[];
};

export type Intent = { id: string; kind: string; status: string; subject?: string; error?: string; received_at: string; duration_ms: number };

export type VaultInfo = { address: string; mount: string; prefix: string; method: string };
export type Secrets = { configured: boolean; vault?: VaultInfo; health?: VaultHealth; refs: string[]; truncated?: boolean; error?: string };

export type Settings = {
  account: { username: string; totp_enabled: boolean; created_at: string };
  agent: Record<string, string | number>;
  vault?: VaultInfo;
};

export function when(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
