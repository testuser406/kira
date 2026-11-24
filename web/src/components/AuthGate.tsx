import { useCallback, useEffect, useState } from "react";
import { Button, Card, Input } from "./ui";

type Me = { username: string; role: "admin" | "viewer"; auth_disabled?: boolean };
type UserRow = { id: string; username: string; role: string; disabled: boolean; last_login_at: string | null };

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(data.error ?? `Request failed (${res.status})`);
  return data as T;
}

function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("POST", "/auth/login", { username, password });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#070b14] px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-2xl border border-white/10 bg-white/[0.03] p-6">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Kira</h1>
          <p className="text-xs text-slate-500">Sophos Firewall reporting — sign in to continue</p>
        </div>
        <label className="block text-xs text-slate-400">
          Username
          <Input className="mt-1 w-full" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="block text-xs text-slate-400">
          Password
          <Input className="mt-1 w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <p className="text-xs text-rose-300" role="alert">{error}</p>}
        <Button type="submit" className="w-full" disabled={busy || !username || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}

function Account({ me, onClose, onSignedOut }: { me: Me; onClose: () => void; onSignedOut: () => void }) {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [nu, setNu] = useState({ username: "", password: "", role: "viewer" });

  const loadUsers = useCallback(async () => {
    if (me.role !== "admin" || me.auth_disabled) return;
    try {
      setUsers((await call<{ rows: UserRow[] }>("GET", "/users")).rows);
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed to load users" });
    }
  }, [me]);
  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const run = async (fn: () => Promise<unknown>, okText: string, after?: () => void) => {
    try {
      await fn();
      setMsg({ ok: true, text: okText });
      after?.();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed" });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/60 p-4" onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()} className="w-full max-w-lg">
        <Card>
          <div className="space-y-5 p-5 text-xs text-slate-300">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100">Account — {me.username} ({me.role})</h2>
              <Button size="sm" variant="secondary" onClick={onClose}>Close</Button>
            </div>
            {msg && <p className={msg.ok ? "text-emerald-300" : "text-rose-300"} role="status">{msg.text}</p>}

            {!me.auth_disabled && (
              <section className="space-y-2">
                <h3 className="font-medium text-slate-200">Change password</h3>
                <Input className="w-full" type="password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} />
                <Input className="w-full" type="password" placeholder="New password (10+ characters)" value={next} onChange={(e) => setNext(e.target.value)} />
                <Button
                  disabled={!cur || next.length < 10}
                  onClick={() => run(() => call("POST", "/auth/password", { current_password: cur, new_password: next }), "Password changed. Signing out…", () => setTimeout(onSignedOut, 800))}
                >
                  Change password
                </Button>
              </section>
            )}

            {me.role === "admin" && !me.auth_disabled && (
              <section className="space-y-2">
                <h3 className="font-medium text-slate-200">Users</h3>
                <ul className="divide-y divide-white/[0.06] rounded-lg border border-white/10">
                  {users.map((u) => (
                    <li key={u.id} className="flex items-center justify-between gap-2 px-3 py-2">
                      <span>
                        {u.username} <span className="text-slate-500">· {u.role}{u.disabled ? " · disabled" : ""}</span>
                      </span>
                      <span className="flex gap-1">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => {
                            const pw = window.prompt(`New password for ${u.username} (10+ characters)`);
                            if (pw) void run(() => call("PUT", `/users/${u.id}/password`, { password: pw }), "Password reset");
                          }}
                        >
                          Reset
                        </Button>
                        {u.username !== me.username && (
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => {
                              if (window.confirm(`Delete ${u.username}?`)) void run(() => call("DELETE", `/users/${u.id}`), "User deleted", loadUsers);
                            }}
                          >
                            Delete
                          </Button>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
                <div className="flex flex-wrap gap-2">
                  <Input placeholder="username" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} />
                  <Input type="password" placeholder="password (10+)" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} />
                  <select
                    value={nu.role}
                    onChange={(e) => setNu({ ...nu, role: e.target.value })}
                    className="rounded-lg border border-white/10 bg-[#070b14] px-2 py-1.5 text-xs text-slate-200"
                  >
                    <option value="viewer">viewer (read-only)</option>
                    <option value="admin">admin</option>
                  </select>
                  <Button
                    disabled={!nu.username || nu.password.length < 10}
                    onClick={() => run(() => call("POST", "/users", nu), "User created", () => { setNu({ username: "", password: "", role: "viewer" }); void loadUsers(); })}
                  >
                    Add user
                  </Button>
                </div>
              </section>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

/** Wraps the app: shows the sign-in page until a session exists, and a small account menu afterwards. */
export default function AuthGate({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null | undefined>(undefined); // undefined = checking, null = signed out
  const [open, setOpen] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setMe(await call<Me>("GET", "/auth/me"));
    } catch {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
    // Any API call that comes back 401 (expired session) returns the user to sign-in.
    const original = window.fetch;
    window.fetch = async (...args) => {
      const res = await original(...args);
      const url = String(args[0] instanceof Request ? args[0].url : args[0]);
      if (res.status === 401 && url.includes("/api/") && !url.includes("/auth/login")) setMe(null);
      return res;
    };
    return () => {
      window.fetch = original;
    };
  }, [refresh]);

  const signOut = async () => {
    try {
      await call("POST", "/auth/logout");
    } catch {
      /* already signed out */
    }
    setOpen(false);
    setMe(null);
  };

  if (me === undefined) return <div className="min-h-screen bg-[#070b14]" />;
  if (me === null) return <Login onDone={refresh} />;
  return (
    <>
      {children}
      <div className="fixed bottom-3 left-3 z-40 flex items-center gap-2 rounded-full border border-white/10 bg-[#0b1220]/90 px-3 py-1.5 text-[11px] text-slate-400 backdrop-blur">
        <span>{me.auth_disabled ? "Auth disabled" : `${me.username} · ${me.role}`}</span>
        <button className="text-emerald-300 hover:underline" onClick={() => setOpen(true)}>Account</button>
        {!me.auth_disabled && <button className="text-slate-300 hover:underline" onClick={signOut}>Sign out</button>}
      </div>
      {open && <Account me={me} onClose={() => setOpen(false)} onSignedOut={signOut} />}
    </>
  );
}
