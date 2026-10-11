import { useEffect, useState } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";

const API = import.meta.env.VITE_API || "http://localhost:8000";
const POLL_MS = 3000;
const SEV_COLOR = { critical: "#ff4d6d", high: "#ff9f1c", medium: "#ffd23f", low: "#4cc9f0" };

const hhmm = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const hhmmss = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const sum = (rows, key) => rows.reduce((n, r) => n + r[key], 0);
const countOf = (rows, sev) => rows.find((r) => r.severity === sev)?.alerts ?? 0;

function Card({ label, value, color }) {
  return (
    <div className="card">
      <div className="card-label">{label}</div>
      <div className="card-value" style={{ color }}>{value}</div>
    </div>
  );
}

function Panel({ title, children, wide }) {
  return (
    <section className={"panel" + (wide ? " wide" : "")}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

const tip = { contentStyle: { background: "#0b1220", border: "1px solid #24324d", borderRadius: 6 }, cursor: { fill: "#ffffff10" } };

export default function App() {
  const [minutes, setMinutes] = useState(60);
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [online, setOnline] = useState(true);

  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const [s, a, e] = await Promise.all([
          fetch(`${API}/api/stats?minutes=${minutes}`).then((r) => r.json()),
          fetch(`${API}/api/alerts?limit=30`).then((r) => r.json()),
          fetch(`${API}/api/events?limit=40`).then((r) => r.json()),
        ]);
        if (stop) return;
        setStats(s); setAlerts(a); setEvents(e); setOnline(true);
      } catch {
        if (!stop) setOnline(false);
      }
    };
    load();
    const id = setInterval(load, POLL_MS);
    return () => { stop = true; clearInterval(id); };
  }, [minutes]);

  const timeline = (stats?.timeline ?? []).map((p) => ({ ...p, label: hhmm(p.t) }));
  const bySev = stats?.alerts_by_severity ?? [];

  return (
    <div className="app">
      <header>
        <h1>mini-siem</h1>
        <div className="right">
          <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            <option value={15}>last 15 min</option>
            <option value={60}>last 1 hour</option>
            <option value={360}>last 6 hours</option>
            <option value={1440}>last 24 hours</option>
          </select>
          <span className={"dot " + (online ? "on" : "off")} />
          <span className="muted">{online ? "live" : "API offline"}</span>
        </div>
      </header>

      <div className="cards">
        <Card label="Events" value={sum(timeline, "events")} />
        <Card label="Alerts" value={sum(bySev, "alerts")} color="#ff9f1c" />
        <Card label="Critical" value={countOf(bySev, "critical")} color={SEV_COLOR.critical} />
        <Card label="High" value={countOf(bySev, "high")} color={SEV_COLOR.high} />
      </div>

      <div className="grid">
        <Panel title="Events over time" wide>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timeline}>
              <CartesianGrid stroke="#1b2740" vertical={false} />
              <XAxis dataKey="label" stroke="#7d8db0" fontSize={12} />
              <YAxis stroke="#7d8db0" fontSize={12} allowDecimals={false} />
              <Tooltip {...tip} />
              <Area type="monotone" dataKey="events" stroke="#4cc9f0" fill="#4cc9f033" />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Top source IPs">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={stats?.top_ips ?? []} layout="vertical" margin={{ left: 30 }}>
              <XAxis type="number" stroke="#7d8db0" fontSize={12} allowDecimals={false} />
              <YAxis type="category" dataKey="src_ip" stroke="#7d8db0" fontSize={12} width={110} />
              <Tooltip {...tip} />
              <Bar dataKey="events" fill="#4cc9f0" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Alerts by rule">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={stats?.alerts_by_rule ?? []} layout="vertical" margin={{ left: 40 }}>
              <XAxis type="number" stroke="#7d8db0" fontSize={12} allowDecimals={false} />
              <YAxis type="category" dataKey="rule_id" stroke="#7d8db0" fontSize={12} width={150} />
              <Tooltip {...tip} />
              <Bar dataKey="alerts" fill="#ff9f1c" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Live alerts" wide>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Hits</th><th>Description</th></tr></thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td>{hhmmss(a.ts)}</td>
                    <td><span className="badge" style={{ background: SEV_COLOR[a.severity] }}>{a.severity}</span></td>
                    <td>{a.rule_id}</td>
                    <td>{a.group_key}</td>
                    <td>{a.count}/{a.window_s}s</td>
                    <td className="muted">{a.description}</td>
                  </tr>
                ))}
                {alerts.length === 0 && <tr><td colSpan="6" className="muted">no alerts yet</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Recent events" wide>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>IP</th><th>Request</th><th>Status</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td>{hhmmss(e.ts)}</td>
                    <td>{e.source}</td>
                    <td>{e.event_type}</td>
                    <td>{e.src_ip}</td>
                    <td className="path">{e.method ? `${e.method} ${e.path}` : e.username ?? ""}</td>
                    <td>{e.status ?? ""}</td>
                  </tr>
                ))}
                {events.length === 0 && <tr><td colSpan="6" className="muted">no events yet</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
