import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, LogOut, RefreshCw, Download, Lock, Link2, Building2 } from 'lucide-react';

// Administrator dashboard (panel revision): tracks and reports how many Safe,
// Spam, and Malicious messages Bantay-Bait has caught. Reached at /admin.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://bantay-bait.onrender.com';
const TOKEN_KEY = 'bb-admin-token';
const COLORS = { safe: '#d4f570', spam: '#fbbf24', malicious: '#f43f5e' };
const LANG_LABEL = { english: 'English', tagalog: 'Tagalog', taglish: 'Taglish', dialect: 'Regional dialect' };

const readToken = () => { try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } };
const writeToken = (t) => { try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* storage blocked */ } };

const LOGIN_TIMEOUT_MS = 70000; // a sleeping free-tier server can take about a minute to wake
const SLOW_HINT_MS = 5000;

function Login({ onLogin }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [slow, setSlow] = useState(false);

  // Wake the back-end while the administrator types, so the login itself is fast.
  useEffect(() => { fetch(`${API_BASE_URL}/health`).catch(() => {}); }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError(''); setSlow(false);
    const ctrl = new AbortController();
    const abort = setTimeout(() => ctrl.abort(), LOGIN_TIMEOUT_MS);
    const hint = setTimeout(() => setSlow(true), SLOW_HINT_MS);
    try {
      const r = await fetch(`${API_BASE_URL}/api/v1/admin/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }),
        signal: ctrl.signal,
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.detail || `Login failed (${r.status}). Please try again.`);
      onLogin(body.token);
    } catch (err) {
      if (err.name === 'AbortError') setError('The server took too long to respond. Please try again.');
      else if (err.message === 'Failed to fetch') setError('Could not reach the server. It may be waking up; try again in a minute.');
      else setError(err.message);
    } finally { clearTimeout(abort); clearTimeout(hint); setBusy(false); setSlow(false); }
  };
  return (
    <div className="min-h-screen bg-[#06231a] flex items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm bg-[#0b382c] border border-[#175d4a] rounded-3xl p-7 space-y-5">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-[#d4f570]/15 border border-[#d4f570]/40"><Lock className="w-5 h-5 text-[#d4f570]" /></div>
          <div>
            <h1 className="font-mono font-black text-white text-lg">Bantay-Bait Admin</h1>
            <p className="text-xs text-emerald-300/70">Administrator dashboard</p>
          </div>
        </div>
        <div className="space-y-1.5">
          <label htmlFor="admin-password" className="text-xs font-bold text-emerald-200">Password</label>
          <input id="admin-password" type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-[#06231a] border border-[#175d4a] rounded-xl px-3.5 py-2.5 text-emerald-100 focus:outline-none focus:ring-2 focus:ring-[#d4f570]" />
        </div>
        {error && <p role="alert" className="text-xs text-rose-300 bg-rose-950/40 border border-rose-800/50 rounded-xl px-3 py-2">{error}</p>}
        {!busy && !error && <p className="text-xs text-emerald-300/80 bg-[#06231a] border border-[#175d4a] rounded-xl px-3 py-2">Note: the server runs on free hosting and sleeps when not in use. The first login after a while may take up to a minute while it wakes up.</p>}
        {busy && slow && <p role="status" className="text-xs text-amber-200 bg-amber-950/30 border border-amber-800/40 rounded-xl px-3 py-2">The server is waking up (free hosting). This can take up to a minute.</p>}
        <button type="submit" disabled={!password || busy}
          className="w-full py-3 rounded-full font-black text-xs bg-[#d4f570] text-[#06231a] disabled:opacity-40">
          {busy ? (slow ? 'Waking up the server…' : 'Logging in…') : 'Log in'}
        </button>
        <a href="/" className="block text-center text-xs text-emerald-400 underline">Back to Bantay-Bait</a>
      </form>
    </div>
  );
}

function StatCard({ label, value, total, color, Icon }) {
  const pct = total ? Math.round((value / total) * 1000) / 10 : 0;
  return (
    <div className="bg-[#0b382c] border border-[#175d4a] rounded-2xl p-4 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold uppercase tracking-wider text-emerald-300/80">{label}</span>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <p className="font-mono font-black text-3xl text-white tabular-nums">{value.toLocaleString()}</p>
      {total != null && <p className="text-xs text-emerald-300/70">{pct}% of all checks</p>}
    </div>
  );
}

function DailyChart({ daily }) {
  const ref = useRef(null);
  const [cw, setCw] = useState(600);
  useEffect(() => {
    if (!ref.current || typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(([e]) => setCw(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  if (!daily.length) return <p className="text-sm text-emerald-300/70">No checks in this period yet.</p>;
  const max = Math.max(...daily.map((d) => d.safe + d.spam + d.malicious), 1);
  const W = Math.max(cw, daily.length * 30), H = 160, barW = Math.min(28, (W / daily.length) * 0.6);
  return (
    <div ref={ref} className="overflow-x-auto">
      <svg width={W} height={H + 38} role="img" aria-label="Checks per day by verdict"><g transform="translate(0,14)">
        {[0.5, 1].map((f) => (
          <g key={f}>
            <line x1="0" x2={W} y1={H - H * f} y2={H - H * f} stroke="#175d4a" strokeDasharray="3 3" />
            <text x="2" y={H - H * f - 3} fontSize="10" fill="#6ee7b7">{Math.round(max * f)}</text>
          </g>
        ))}
        {daily.map((d, i) => {
          const x = i * (W / daily.length) + (W / daily.length - barW) / 2;
          let y = H;
          return (
            <g key={d.date}>
              {['safe', 'spam', 'malicious'].map((v) => {
                const h = (d[v] / max) * H;
                y -= h;
                return h > 0 ? <rect key={v} x={x} y={y} width={barW} height={h} fill={COLORS[v]} rx="2"><title>{`${d.date} ${v}: ${d[v]}`}</title></rect> : null;
              })}
              {(i % Math.max(1, Math.ceil((daily.length * 46) / W)) === 0) && (
                <text x={x + barW / 2} y={H + 15} fontSize="10" fill="#a7f3d0" textAnchor="middle">{d.date.slice(5)}</text>
              )}
            </g>
          );
        })}
      </g></svg>
    </div>
  );
}

function RankList({ title, Icon, rows, empty }) {
  const max = Math.max(...rows.map((r) => r[1]), 1);
  return (
    <div className="bg-[#0b382c] border border-[#175d4a] rounded-2xl p-4 space-y-3">
      <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-300/80 flex items-center space-x-2"><Icon className="w-4 h-4 text-[#d4f570]" /><span>{title}</span></h3>
      {rows.length === 0 ? <p className="text-sm text-emerald-300/70">{empty}</p> : (
        <ul className="space-y-2">
          {rows.map(([name, n]) => (
            <li key={name} className="text-sm">
              <div className="flex justify-between gap-3 text-emerald-100"><span className="truncate">{name}</span><span className="font-mono tabular-nums">{n}</span></div>
              <div className="h-1.5 rounded-full bg-[#06231a] mt-1"><div className="h-full rounded-full bg-[#d4f570]" style={{ width: `${(n / max) * 100}%` }} /></div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function Admin() {
  const [token, setToken] = useState(readToken());
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState('');
  const [stats, setStats] = useState(null);
  const [messages, setMessages] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const logout = useCallback(() => { writeToken(''); setToken(''); setStats(null); }, []);
  const api = useCallback(async (path) => {
    const r = await fetch(`${API_BASE_URL}/api/v1/admin/${path}`, { headers: { Authorization: `Bearer ${token}` } });
    if (r.status === 401) { logout(); throw new Error('Your session expired. Please log in again.'); }
    if (!r.ok) throw new Error(`Request failed (${r.status})`);
    return r;
  }, [token, logout]);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true); setError('');
    try {
      const [s, m] = await Promise.all([
        api(`stats?days=${days}`).then((r) => r.json()),
        api(`messages?days=${days}&limit=100${filter ? `&verdict=${filter}` : ''}`).then((r) => r.json()),
      ]);
      setStats(s); setMessages(m.messages);
    } catch (err) { setError(err.message); } finally { setLoading(false); }
  }, [token, days, filter, api]);

  useEffect(() => { load(); }, [load]);

  const downloadReport = async () => {
    try {
      const blob = await (await api(`report.csv?days=${days}`)).blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `bantay-bait-report-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) { setError(err.message); }
  };

  if (!token) return <Login onLogin={(t) => { writeToken(t); setToken(t); }} />;

  const total = stats?.total ?? 0;
  return (
    <div className="min-h-screen bg-[#06231a] text-emerald-100">
      <header className="border-b border-[#135342] bg-[#06231a]/95 sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 py-3 flex flex-wrap items-center gap-3 justify-between">
          <div className="flex items-center space-x-2"><Shield className="w-5 h-5 text-[#d4f570]" /><span className="font-mono font-black text-white">Bantay-Bait Admin</span></div>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="period" className="sr-only">Period</label>
            <select id="period" value={days} onChange={(e) => setDays(Number(e.target.value))}
              className="bg-[#0b382c] border border-[#175d4a] rounded-full px-3 py-1.5 text-xs">
              <option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option><option value={90}>Last 90 days</option><option value={0}>All time</option>
            </select>
            <button onClick={load} className="px-3 py-1.5 rounded-full border border-[#175d4a] text-xs flex items-center space-x-1.5"><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /><span>Refresh</span></button>
            <button onClick={downloadReport} className="px-3 py-1.5 rounded-full bg-[#d4f570] text-[#06231a] font-bold text-xs flex items-center space-x-1.5"><Download className="w-3.5 h-3.5" /><span>Download report (CSV)</span></button>
            <button onClick={logout} className="px-3 py-1.5 rounded-full border border-[#175d4a] text-xs flex items-center space-x-1.5"><LogOut className="w-3.5 h-3.5" /><span>Log out</span></button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-5">
        {error && <p className="text-sm text-rose-300 bg-rose-950/40 border border-rose-800/50 rounded-xl px-3 py-2">{error}</p>}
        {!stats && !error && <p className="text-sm text-emerald-300/70">Loading… (the server may take a minute to wake up)</p>}
        {stats && (
          <>
            <section className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <StatCard label="Total checks" value={total} total={null} color="#a7f3d0" Icon={Shield} />
              <StatCard label="Malicious" value={stats.byVerdict.malicious} total={total} color={COLORS.malicious} Icon={ShieldAlert} />
              <StatCard label="Spam" value={stats.byVerdict.spam} total={total} color={COLORS.spam} Icon={AlertTriangle} />
              <StatCard label="Safe" value={stats.byVerdict.safe} total={total} color={COLORS.safe} Icon={ShieldCheck} />
            </section>

            <section className="bg-[#0b382c] border border-[#175d4a] rounded-2xl p-4 space-y-3">
              <div className="flex flex-wrap justify-between gap-2">
                <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-300/80">Checks per day (Philippine time)</h2>
                <div className="flex gap-3 text-xs">
                  {['safe', 'spam', 'malicious'].map((v) => <span key={v} className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-sm" style={{ background: COLORS[v] }} /><span className="capitalize">{v}</span></span>)}
                </div>
              </div>
              <DailyChart daily={stats.daily} />
              <p className="text-xs text-emerald-300/70">
                {stats.downgraded} downgraded from Malicious to Spam by the 0.75 rule · {stats.withLink} checks contained a link
              </p>
            </section>

            <section className="grid md:grid-cols-3 gap-3">
              <RankList title="Most impersonated brands" Icon={Building2} rows={stats.topBrands} empty="No brands found in flagged messages yet." />
              <RankList title="Most common scam/spam link domains" Icon={Link2} rows={stats.topDomains} empty="No links in flagged messages yet." />
              <RankList title="Languages" Icon={Shield} rows={Object.entries(stats.byLanguage).map(([k, n]) => [LANG_LABEL[k] || k, n]).sort((a, b) => b[1] - a[1])} empty="No checks yet." />
            </section>

            <section className="bg-[#0b382c] border border-[#175d4a] rounded-2xl p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-300/80">Flagged messages (personal details masked)</h2>
                <div className="flex gap-1.5">
                  {[['', 'All'], ['malicious', 'Malicious'], ['spam', 'Spam']].map(([v, l]) => (
                    <button key={l} onClick={() => setFilter(v)} aria-pressed={filter === v}
                      className={`px-3 py-1 rounded-full text-xs border ${filter === v ? 'bg-[#d4f570] text-[#06231a] border-[#d4f570] font-bold' : 'border-[#175d4a]'}`}>{l}</button>
                  ))}
                </div>
              </div>
              {messages.length === 0 ? <p className="text-sm text-emerald-300/70">No flagged messages in this period. Safe messages are counted but never saved.</p> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="text-left text-xs text-emerald-300/80 border-b border-[#175d4a]">
                      <th className="py-2 pr-3">Time</th><th className="py-2 pr-3">Verdict</th><th className="py-2 pr-3">Conf.</th><th className="py-2 pr-3">Language</th><th className="py-2">Message</th>
                    </tr></thead>
                    <tbody>
                      {messages.map((m) => (
                        <tr key={m.id} className="border-b border-[#135342] align-top">
                          <td className="py-2 pr-3 whitespace-nowrap text-xs text-emerald-300/80">{new Date(m.createdAt).toLocaleString('en-PH', { dateStyle: 'medium', timeStyle: 'short' })}</td>
                          <td className="py-2 pr-3"><span className="px-2 py-0.5 rounded-full text-xs font-bold text-[#06231a]" style={{ background: COLORS[m.verdict] }}>{m.verdict}{m.downgraded ? ' ↓' : ''}</span></td>
                          <td className="py-2 pr-3 font-mono text-xs tabular-nums">{Math.round(m.confidence * 100)}%</td>
                          <td className="py-2 pr-3 text-xs">{LANG_LABEL[m.language] || m.language}</td>
                          <td className="py-2 break-words min-w-[16rem]">{m.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}
