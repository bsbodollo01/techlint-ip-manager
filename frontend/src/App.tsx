import { useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import {
  addIpRecord,
  deleteIpRecord,
  fetchAuditLog,
  fetchIpRecords,
  getStoredUser,
  login,
  logout,
  updateIpLabel,
} from './api';
import type { AuditEvent, IpRecord, User } from './types';

function App() {
  const [user, setUser] = useState<User | null>(getStoredUser());
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [ips, setIps] = useState<IpRecord[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEvent[]>([]);
  const [newIp, setNewIp] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [newComment, setNewComment] = useState('');
  const [editMap, setEditMap] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(false);

  const isSuperAdmin = useMemo(() => user?.role === 'super_admin', [user]);

  useEffect(() => {
    if (user) {
      loadData();
    }
  }, [user]);

  const loadData = async () => {
    setLoading(true);
    try {
      const records = await fetchIpRecords();
      setIps(records);
      if (isSuperAdmin) {
        const logs = await fetchAuditLog();
        setAuditLog(logs);
      }
      setError('');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    setInfo('');

    try {
      const signedInUser = await login(email, password);
      setUser(signedInUser);
      setEmail('');
      setPassword('');
      setInfo('Logged in successfully.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    setError('');
    try {
      await logout();
      setUser(null);
      setIps([]);
      setAuditLog([]);
      setInfo('Logged out.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleAddIp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    setInfo('');
    try {
      await addIpRecord(newIp, newLabel, newComment);
      setNewIp('');
      setNewLabel('');
      setNewComment('');
      await loadData();
      setInfo('IP address added.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateLabel = async (id: number) => {
    const label = editMap[id];
    if (!label) return;
    setLoading(true);
    setError('');
    setInfo('');
    try {
      await updateIpLabel(id, label);
      await loadData();
      setInfo('Label updated.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: number) => {
    const confirmDelete = window.confirm('Delete this IP entry?');
    if (!confirmDelete) return;
    setLoading(true);
    setError('');
    setInfo('');
    try {
      await deleteIpRecord(id);
      await loadData();
      setInfo('IP record deleted.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-50 px-4 py-12 text-slate-900 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-md rounded-[32px] border border-slate-200 bg-white p-8 shadow-xl shadow-slate-200/60">
          <div className="space-y-3">
            <h1 className="text-3xl font-semibold tracking-tight">IP Manager Login</h1>
            <p className="text-sm text-slate-600">Sign in to manage IP addresses, labels, and audit history.</p>
          </div>

          <form onSubmit={handleLogin} className="mt-8 space-y-5">
            <label className="block text-sm font-medium text-slate-700">
              Email
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                required
                className="mt-2 w-full rounded-2xl border border-slate-300 bg-slate-50 px-4 py-3 text-slate-900 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
              />
            </label>
            <label className="block text-sm font-medium text-slate-700">
              Password
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                required
                className="mt-2 w-full rounded-2xl border border-slate-300 bg-slate-50 px-4 py-3 text-slate-900 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
              />
            </label>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex w-full items-center justify-center rounded-2xl bg-slate-950 px-4 py-3 mt-5 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <div className="mt-6 rounded-2xl bg-slate-50 p-4 text-sm text-slate-600 ring-1 ring-slate-200">
            <strong className="font-semibold text-slate-900">Super admin</strong>
            <div>admin@example.com / Admin123!</div>
          </div>

          {error && <div className="mt-4 rounded-2xl bg-rose-50 px-4 py-3 text-sm font-medium text-rose-700 ring-1 ring-rose-200">{error}</div>}
          {info && <div className="mt-4 rounded-2xl bg-sky-50 px-4 py-3 text-sm font-medium text-sky-700 ring-1 ring-sky-200">{info}</div>}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 px-4 py-8 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <header className="rounded-[32px] border border-slate-200 bg-white p-6 shadow-sm shadow-slate-200/60 sm:flex sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-sky-600">IP Management</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Manage addresses and audit logs</h1>
            <p className="mt-2 text-sm text-slate-600">Logged in as <strong>{user.email}</strong> ({user.role})</p>
          </div>
          <button
            onClick={handleLogout}
            disabled={loading}
            className="mt-5 inline-flex items-center justify-center rounded-2xl bg-slate-950 px-5 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-70 sm:mt-0"
          >
            Logout
          </button>
        </header>

        <div className="grid gap-6 xl:grid-cols-[380px_minmax(0,1fr)]">
          <section className="rounded-[32px] border border-slate-200 bg-white p-6 shadow-sm shadow-slate-200/60">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-950">Add New IP</h2>
                <p className="mt-1 text-sm text-slate-600">Submit an IP address, label, and optional note.</p>
              </div>
            </div>
            <form onSubmit={handleAddIp} className="mt-6 space-y-4">
              <label className="block text-sm font-medium text-slate-700">
                IP Address
                <input
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  required
                  className="mt-2 w-full rounded-2xl border border-slate-300 bg-slate-50 px-4 py-3 text-slate-900 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
                />
              </label>
              <label className="block text-sm font-medium text-slate-700">
                Label
                <input
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  required
                  className="mt-2 w-full rounded-2xl border border-slate-300 bg-slate-50 px-4 py-3 text-slate-900 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
                />
              </label>
              <label className="block text-sm font-medium text-slate-700">
                Comment (optional)
                <input
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-300 bg-slate-50 px-4 py-3 text-slate-900 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
                />
              </label>
              <button
                type="submit"
                disabled={loading}
                className="inline-flex w-full items-center justify-center rounded-2xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-70"
              >
                Add IP
              </button>
            </form>
          </section>

          <section className="rounded-[32px] border border-slate-200 bg-white p-6 shadow-sm shadow-slate-200/60">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-950">IP Records</h2>
                <p className="mt-1 text-sm text-slate-600">View every stored IP address and its label.</p>
              </div>
            </div>

            {loading && <div className="mt-4 rounded-2xl bg-slate-50 px-4 py-3 text-sm text-slate-700">Loading…</div>}
            <div className="mt-6 overflow-x-auto rounded-[28px] border border-slate-200">
              <table className="min-w-full border-collapse text-left text-sm text-slate-700">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="px-4 py-3 font-semibold">IP</th>
                    <th className="px-4 py-3 font-semibold">Label</th>
                    <th className="px-4 py-3 font-semibold">Comment</th>
                    <th className="px-4 py-3 font-semibold">Owner</th>
                    <th className="px-4 py-3 font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 bg-white">
                  {ips.map((record) => {
                    const editable = user.role === 'super_admin' || record.owner_user_id === user.id;
                    return (
                      <tr key={record.id}>
                        <td className="px-4 py-4 text-slate-900">{record.ip}</td>
                        <td className="px-4 py-4">
                          {editable ? (
                            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                              <input
                                value={editMap[record.id] ?? record.label}
                                onChange={(e) => setEditMap((prev) => ({ ...prev, [record.id]: e.target.value }))}
                                className="w-full min-w-[140px] rounded-2xl border border-slate-300 bg-slate-50 px-3 py-2 text-slate-900 outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
                              />
                              <button
                                type="button"
                                onClick={() => handleUpdateLabel(record.id)}
                                className="inline-flex items-center justify-center rounded-2xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700"
                              >
                                Save
                              </button>
                            </div>
                          ) : (
                            record.label
                          )}
                        </td>
                        <td className="px-4 py-4 text-slate-600">{record.comment}</td>
                        <td className="px-4 py-4 text-slate-600">{record.owner_email}</td>
                        <td className="px-4 py-4">
                          {isSuperAdmin && (
                            <button
                              type="button"
                              onClick={() => handleDelete(record.id)}
                              className="rounded-2xl bg-rose-600 px-3 py-2 text-sm font-semibold text-white transition hover:bg-rose-700"
                            >
                              Delete
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        {isSuperAdmin && (
          <section className="rounded-[32px] border border-slate-200 bg-white p-6 shadow-sm shadow-slate-200/60">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-950">Audit Log</h2>
                <p className="mt-1 text-sm text-slate-600">View session and IP change history for the system.</p>
              </div>
            </div>
            <div className="mt-6 overflow-x-auto rounded-[28px] border border-slate-200">
              <table className="min-w-full border-collapse text-left text-sm text-slate-700">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Date</th>
                    <th className="px-4 py-3 font-semibold">Type</th>
                    <th className="px-4 py-3 font-semibold">Actor</th>
                    <th className="px-4 py-3 font-semibold">Target</th>
                    <th className="px-4 py-3 font-semibold">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 bg-white">
                  {auditLog.map((event) => (
                    <tr key={event.id}>
                      <td className="px-4 py-4 text-slate-900">{new Date(event.created_at).toLocaleString()}</td>
                      <td className="px-4 py-4">{event.event_type}</td>
                      <td className="px-4 py-4 text-slate-600">{event.actor_email ?? 'system'}</td>
                      <td className="px-4 py-4 text-slate-600">{event.target_type} {event.target_id ?? ''}</td>
                      <td className="px-4 py-4 text-slate-600">{event.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {error && <div className="rounded-2xl bg-rose-50 px-4 py-3 text-sm font-medium text-rose-700 ring-1 ring-rose-200">{error}</div>}
        {info && <div className="rounded-2xl bg-sky-50 px-4 py-3 text-sm font-medium text-sky-700 ring-1 ring-sky-200">{info}</div>}
      </div>
    </div>
  );
}

export default App;
