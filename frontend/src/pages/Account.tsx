import { useEffect, useState } from "react";
import { AppUser, endpoints } from "../api";
import { useAuth } from "../context/AuthContext";
import { PageHeader, Loading } from "../components/ui";
import { apiErrorMessage } from "../components/training/shared";

const ROLES = ["admin", "security_analyst", "operator", "auditor", "viewer"];
const input = "w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200";

function ChangePassword() {
  const { applyToken, authDisabled } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  if (authDisabled) {
    return <p className="text-sm text-slate-400">Authentication is disabled on this deployment (demo mode), so there is no password to change.</p>;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next !== confirm) { setMsg({ ok: false, text: "The new passwords don't match." }); return; }
    setBusy(true);
    setMsg(null);
    try {
      const r = await endpoints.changePassword(current, next);
      applyToken(r.data.access_token); // old tokens (other sessions) are now invalid
      setCurrent(""); setNext(""); setConfirm("");
      setMsg({ ok: true, text: "Password changed. Other sessions have been signed out." });
    } catch (err) {
      setMsg({ ok: false, text: apiErrorMessage(err, "Could not change the password.") });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="max-w-md space-y-3">
      <input className={input} type="password" placeholder="Current password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
      <input className={input} type="password" placeholder="New password (min 12 characters)" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
      <input className={input} type="password" placeholder="Confirm new password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
      {msg && <div role="alert" className={`text-sm ${msg.ok ? "text-emerald-500" : "text-red-500"}`}>{msg.text}</div>}
      <button className="btn-primary disabled:opacity-40" disabled={busy || !current || !next || !confirm}>{busy ? "Saving…" : "Change password"}</button>
    </form>
  );
}

function UserAdmin() {
  const [users, setUsers] = useState<AppUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => endpoints.listUsers().then((r) => setUsers(r.data)).catch((e) => { setUsers([]); setError(apiErrorMessage(e, "Failed to load users.")); });
  useEffect(() => { load(); }, []);

  async function act(key: string, fn: () => Promise<any>, fail: string) {
    setBusy(key); setError(null);
    try { await fn(); await load(); } catch (e) { setError(apiErrorMessage(e, fail)); } finally { setBusy(null); }
  }

  return (
    <div>
      {error && <div className="mb-3 text-sm text-red-500">{error}</div>}
      <form className="flex gap-3 flex-wrap mb-5"
        onSubmit={(e) => { e.preventDefault(); act("create", async () => { await endpoints.createUser(form.username.trim(), form.password, [form.role]); setForm({ username: "", password: "", role: "viewer" }); }, "Failed to create user."); }}>
        <input className={input + " !w-44"} placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        <input className={input + " !w-56"} type="password" placeholder="Temporary password (12+ chars)" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        <select className={input + " !w-44"} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {ROLES.map((r) => <option key={r} value={r}>{r.replace("_", " ")}</option>)}
        </select>
        <button className="btn-primary disabled:opacity-40" disabled={busy === "create"}>Add user</button>
      </form>
      {!users ? <Loading /> : (
        <div className="overflow-hidden rounded-lg border border-soc-border">
          <table className="w-full text-left text-sm text-slate-400">
            <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
              <tr><th className="px-4 py-3">User</th><th className="px-4 py-3">Role</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Last login</th><th className="px-4 py-3">Actions</th></tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="px-4 py-3 font-mono text-slate-200">{u.username}</td>
                  <td className="px-4 py-3">
                    <select className="bg-soc-panel border border-soc-border rounded px-2 py-1 text-xs text-slate-200" value={u.roles[0]} disabled={!!busy}
                      onChange={(e) => act(u.id, () => endpoints.updateUser(u.id, { roles: [e.target.value] }), "Failed to change role.")}>
                      {ROLES.map((r) => <option key={r} value={r}>{r.replace("_", " ")}</option>)}
                    </select>
                  </td>
                  <td className="px-4 py-3">{u.is_active ? (u.locked ? "Locked" : "Active") : "Disabled"}</td>
                  <td className="px-4 py-3 text-xs">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "never"}</td>
                  <td className="px-4 py-3 flex gap-3">
                    <button className="text-cyan-400 hover:underline" disabled={!!busy}
                      onClick={() => act(u.id, () => endpoints.updateUser(u.id, { is_active: !u.is_active }), "Failed to update user.")}>
                      {u.is_active ? "Disable" : "Enable"}{u.locked && u.is_active ? "" : ""}
                    </button>
                    <button className="text-amber-400 hover:underline" disabled={!!busy}
                      onClick={() => { const p = window.prompt(`New password for ${u.username} (12+ characters):`); if (p) act(u.id, () => endpoints.resetUserPassword(u.id, p), "Failed to reset password."); }}>
                      Reset password
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function Account() {
  const { username, role, tenantName, hasRole } = useAuth();
  return (
    <div>
      <PageHeader title="Account" subtitle={`${username || "Unknown"} · ${(role || "no role").replace("_", " ")}${tenantName ? ` · ${tenantName}` : ""}`} />
      <div className="px-8 pb-8 space-y-10">
        <section>
          <h2 className="text-lg font-semibold text-slate-100 mb-3">Change password</h2>
          <ChangePassword />
        </section>
        {hasRole("admin") && (
          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Users</h2>
            <UserAdmin />
          </section>
        )}
      </div>
    </div>
  );
}
