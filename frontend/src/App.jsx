import { useCallback, useEffect, useRef, useState } from "react";

const post = (url, body) =>
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }).then((r) => r.json());

const clock = (ts) => {
  const s = Math.floor(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`;
};
const pretty = (k) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const LABELS = { log_prompt_injection: "Prompt injection on AI", full_intrusion: "Full intrusion", c2_beacon: "Malware beacon", data_exfil: "Data theft", dns_tunnel: "DNS tunnel", web_injection: "Web injection" };
const SUGGESTIONS = ["What should I handle first?", "Give me a summary", "What is DNS tunneling?"];

function Severity({ level }) {
  return <span className={`sev sev-${level}`}>{level}</span>;
}

function Stat({ label, value, accent }) {
  return (
    <div className={`stat ${accent ? "stat-accent" : ""}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

function Traffic({ data }) {
  const [hover, setHover] = useState(null);
  const W = 640, H = 150, pad = 26, slots = 48;
  const rows = data.slice(-slots);
  const max = Math.max(10, ...rows.map((d) => d.normal + d.flagged));
  const bw = (W - pad) / slots;
  const y = (v) => (v / max) * (H - 14);
  const active = hover != null ? rows[hover] : null;
  return (
    <div className="chart">
      <div className="legend">
        <span><i className="key key-normal" /> Normal</span>
        <span><i className="key key-flagged" /> From flagged sources</span>
        <span className="legend-note">events per 10 simulated seconds</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H + 4}`} role="img" aria-label="Log events over time, split into normal and flagged" onMouseLeave={() => setHover(null)}>
        {[0, .5, 1].map((f) => (
          <g key={f}>
            <line x1={pad} x2={W} y1={H - f * (H - 14)} y2={H - f * (H - 14)} className="grid" />
            <text x={pad - 6} y={H - f * (H - 14) + 3} textAnchor="end" className="tick">{Math.round(f * max)}</text>
          </g>
        ))}
        {rows.map((d, i) => {
          const x = pad + i * bw, n = y(d.normal), f = y(d.flagged), w = Math.max(bw - 2, 2);
          return (
            <g key={d.t} onMouseEnter={() => setHover(i)}>
              <rect x={x} y={0} width={bw} height={H} fill="transparent" />
              {d.normal > 0 && <rect x={x} y={H - n} width={w} height={n} rx={2} className="bar-normal" />}
              {d.flagged > 0 && <rect x={x} y={H - n - f - (n ? 2 : 0)} width={w} height={f} rx={2} className="bar-flagged" />}
            </g>
          );
        })}
      </svg>
      {active && <div className="tip" style={{ left: `${Math.min(((hover + .5) / slots) * 100, 76)}%` }}>{clock(active.t)}<br />{active.normal} normal, {active.flagged} flagged</div>}
    </div>
  );
}

function Report({ id, version }) {
  const [rep, setRep] = useState(null);
  useEffect(() => {
    if (id) fetch(`/api/incidents/${id}`).then((r) => (r.ok ? r.json() : null)).then(setRep);
  }, [id, version]);
  if (!rep) return <p className="empty">Select an incident to read the analyst's report.</p>;
  return (
    <div className="report">
      <header>
        <div><span className="mono dim">{rep.id}</span><h3>{rep.title}</h3></div>
        <Severity level={rep.severity} />
      </header>
      <p className="summary">{rep.summary}</p>
      <p className="why">{rep.severity_reason}</p>
      <h4>Attack timeline</h4>
      <ol className="timeline">
        {rep.timeline.map((a) => (
          <li key={a.id}>
            <span className="mono dim">{clock(a.ts)}</span>
            <div>
              <strong>{a.technique_name}</strong> <span className="mitre">{a.technique}</span>
              <p>{a.reason}{a.hits > 1 ? ` (seen ${a.hits} times)` : ""}</p>
              {a.sample && <code>{a.sample}</code>}
            </div>
          </li>
        ))}
      </ol>
      <h4>Recommended response</h4>
      <ul className="actions">{rep.actions.map((a) => <li key={a}>{a}</li>)}</ul>
      <p className="source">Written by: {rep.analyst} analyst. Sources: {rep.sources.map((s) => s.title).join(", ")}.</p>
    </div>
  );
}

function Chat({ onOpen }) {
  const [log, setLog] = useState([{ who: "vigil", text: "Ask me about an IP, an incident, or what to handle first. I only answer from the alerts and my knowledge base." }]);
  const [text, setText] = useState("");
  const box = useRef(null);
  const ask = async (q) => {
    if (!q.trim()) return;
    setText("");
    setLog((l) => [...l, { who: "you", text: q }]);
    const r = await post("/api/chat", { question: q });
    setLog((l) => [...l, { who: "vigil", text: r.answer, refs: r.refs }]);
  };
  useEffect(() => { box.current?.scrollTo({ top: box.current.scrollHeight, behavior: "smooth" }); }, [log]);
  return (
    <section className="panel chat">
      <h2>Ask Vigil</h2>
      <div className="messages" ref={box}>
        {log.map((m, i) => (
          <div key={i} className={`msg msg-${m.who}`}>
            {m.text}
            {m.refs?.filter((r) => r.startsWith("INC")).map((r) => <button key={r} className="ref" onClick={() => onOpen(r)}>{r}</button>)}
          </div>
        ))}
      </div>
      <div className="chips">{SUGGESTIONS.map((s) => <button key={s} onClick={() => ask(s)}>{s}</button>)}</div>
      <form onSubmit={(e) => { e.preventDefault(); ask(text); }}>
        <input value={text} onChange={(e) => setText(e.target.value)} maxLength={500} placeholder="Why is this IP dangerous?" aria-label="Ask a question" />
        <button type="submit">Ask</button>
      </form>
    </section>
  );
}

export default function App() {
  const [state, setState] = useState(null);
  const [feed, setFeed] = useState([]);
  const [selected, setSelected] = useState(null);
  const [scenarios, setScenarios] = useState({});
  const [online, setOnline] = useState(false);
  const picked = useRef(false);

  const apply = useCallback((s) => {
    setState(s);
    if (!picked.current && s.incidents.length) setSelected(s.incidents[0].id);
  }, []);

  useEffect(() => {
    fetch("/api/state").then((r) => r.json()).then((s) => { setScenarios(s.scenarios); setFeed(s.feed.slice().reverse()); apply(s); });
    const es = new EventSource("/api/stream");
    es.onopen = () => setOnline(true);
    es.onerror = () => setOnline(false);
    es.onmessage = (m) => {
      const d = JSON.parse(m.data);
      if (d.state) apply(d.state);
      if (d.events?.length) setFeed((f) => [...d.events.slice().reverse(), ...f].slice(0, 16));
    };
    return () => es.close();
  }, [apply]);

  const open = (id) => { picked.current = true; setSelected(id); };
  const reset = async () => { await post("/api/reset"); picked.current = false; setSelected(null); setFeed([]); };
  if (!state) return <div className="boot">Starting Vigil...</div>;

  const incidents = state.incidents;
  const critical = incidents.filter((i) => i.severity === "critical").length;
  const current = incidents.find((i) => i.id === selected);
  const version = current ? `${current.alert_ids.length}-${current.severity}` : "";
  const detected = state.attacks.filter((a) => a.detected_after != null);
  const lastDetect = detected.length ? `${detected[detected.length - 1].detected_after}s` : "-";

  return (
    <div className="app">
      <header className="top">
        <div className="brand"><span className="mark">V</span><div><strong>VIGIL</strong><small>AI security analyst</small></div></div>
        <div className="status"><span className={`dot ${online ? "on" : ""}`} />{online ? "Monitoring" : "Reconnecting"} <span className="mono dim">{clock(state.now)}</span></div>
        <div className="notice">Simulated data only</div>
        <div className="controls">
          <label>Speed
            <select value={state.speed} onChange={(e) => post("/api/speed", { speed: Number(e.target.value) })}>
              {[5, 15, 30, 60].map((s) => <option key={s} value={s}>{s}x</option>)}
              {![5, 15, 30, 60].includes(state.speed) && <option value={state.speed}>{state.speed}x</option>}
            </select>
          </label>
          <button onClick={reset}>Reset</button>
        </div>
      </header>

      <div className="stats">
        <Stat label="Events processed" value={state.events_seen.toLocaleString("en-US")} />
        <Stat label="Alerts" value={state.alert_count} />
        <Stat label="Incidents" value={incidents.length} />
        <Stat label="Critical" value={critical} accent={critical > 0} />
        <Stat label="Last detection" value={lastDetect} />
      </div>

      <main className="grid">
        <aside className="col">
          <section className="panel attacks">
            <h2>Launch a fake attack</h2>
            <div className="attack-list">
              {Object.entries(scenarios).map(([key, text]) => (
                <button key={key} className={key === "full_intrusion" ? "attack hero" : "attack"} data-scenario={key} onClick={() => post("/api/simulate", { scenario: key })}>
                  <strong>{LABELS[key] ?? pretty(key)}</strong><span>{text}</span>
                </button>
              ))}
            </div>
          </section>
          <section className="panel launched">
            <h2>Test results</h2>
            {state.attacks.length === 0 && <p className="empty">No attacks launched yet.</p>}
            <ul>{state.attacks.slice().reverse().slice(0, 5).map((a) => (
              <li key={a.id}><span>{LABELS[a.scenario] ?? pretty(a.scenario)}</span>
                {a.detected_after != null ? <b className="caught">Caught in {a.detected_after}s</b> : <b className="dim">Running...</b>}</li>
            ))}</ul>
          </section>
        </aside>

        <section className="col center">
          <section className="panel"><h2>Live traffic</h2><Traffic data={state.traffic} /></section>
          <section className="panel feed-panel">
            <h2>Log stream</h2>
            <div className="feed">{feed.map((e, i) => (
              <div key={`${e.ts}-${i}`} className={e.flagged ? "line flagged" : "line"}>
                <span>{clock(e.ts)}</span><span>{e.source}</span><span>{e.src_ip}</span><span>{e.text}</span>
              </div>
            ))}</div>
          </section>
          <section className="panel incidents">
            <h2>Incidents</h2>
            {incidents.length === 0 && <p className="empty">Quiet so far. Launch a fake attack to test detection.</p>}
            <div className="inc-list">{incidents.map((i) => (
              <button key={i.id} className={i.id === selected ? "inc active" : "inc"} onClick={() => open(i.id)}>
                <Severity level={i.severity} />
                <span className="inc-title">{i.title}</span>
                <span className="mono dim">{i.id}</span>
              </button>
            ))}</div>
          </section>
        </section>

        <aside className="col right">
          <section className="panel report-panel"><h2>Analyst report</h2><Report id={selected} version={version} /></section>
          <Chat onOpen={open} />
        </aside>
      </main>
    </div>
  );
}
