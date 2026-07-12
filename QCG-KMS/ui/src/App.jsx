import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "./api.js";

function Banner({ msg, kind }) {
  if (!msg) return null;
  return <div className={`banner ${kind || "info"}`}>{msg}</div>;
}

function PwInput({ value, onChange, placeholder, onKeyDown }) {
  const [show, setShow] = useState(false);
  return (
    <div className="pw">
      <input type={show ? "text" : "password"} placeholder={placeholder}
             value={value} onChange={onChange} onKeyDown={onKeyDown} />
      <button type="button" className="pw-eye" tabIndex={-1}
              onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </div>
  );
}

function PasswordRules({ pw }) {
  const rules = [
    { ok: pw.length >= 8, label: "At least 8 characters (required)" },
    { ok: /[A-Za-z]/.test(pw), label: "Includes a letter (recommended)" },
    { ok: /[0-9]/.test(pw), label: "Includes a number (recommended)" },
  ];
  return (
    <div className="pwrules">
      <div className="pwrules-title">Password requirements</div>
      <ul>
        {rules.map((r, i) => (
          <li key={i} className={r.ok ? "ok" : ""}>
            <span className="tick">{r.ok ? "✓" : "○"}</span>{r.label}
          </li>
        ))}
      </ul>
    </div>
  );
}

function BrandHead() {
  return (
    <div className="brandhead">
      <img src="/logo.png" alt="Quantum Cloud Guard" className="brandhead-logo"
           onError={(e) => { e.currentTarget.style.display = "none"; }} />
      <h1 className="brandhead-title">
        Quantum Cloud Guard
        <span className="brandhead-sub">Key Management Service</span>
      </h1>
    </div>
  );
}

function AuthGate({ onAuthed }) {
  const [screen, setScreen] = useState("loading"); // loading|setup|login|register|forgot
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [otp, setOtp] = useState("");
  const [needOtp, setNeedOtp] = useState(false);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.needsSetup()
      .then((r) => setScreen(r.needs_setup ? "setup" : "login"))
      .catch(() => setScreen("login"));
  }, []);

  function go(next) {
    setErr(""); setInfo(""); setNeedOtp(false); setOtp(""); setScreen(next);
  }

  async function doSetup() {
    setErr(""); setBusy(true);
    try { await api.setup(u, p); await api.login(u, p); onAuthed(); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  }
  async function doLogin() {
    setErr(""); setBusy(true);
    try { await api.login(u, p, needOtp ? otp : null); onAuthed(); }
    catch (e) {
      if (/one-time code/i.test(e.message)) {
        setNeedOtp(true); setErr("");
        setInfo("Enter the 6-digit code from your authenticator app.");
      } else { setErr(e.message); }
    } finally { setBusy(false); }
  }
  async function doRegister() {
    setErr(""); setBusy(true);
    try {
      const r = await api.register(u, p);
      setScreen("login"); setErr(""); setNeedOtp(false); setP("");
      setInfo(r.message);
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  }
  async function doForgot() {
    setErr(""); setBusy(true);
    try { const r = await api.forgotPassword(u); setInfo(r.message); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  }

  if (screen === "loading") return <div className="center muted">Loading…</div>;

  if (screen === "setup") {
    return (
      <div className="card auth">
        <BrandHead />
        <p className="muted">Welcome. Create the administrator account to get started.
          this first account approves everyone else.</p>
        <Banner msg={err} kind="error" />
        <input placeholder="Choose an admin username" value={u}
               onChange={(e) => setU(e.target.value)} />
        <PwInput placeholder="Choose a password" value={p}
                 onChange={(e) => setP(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && doSetup()} />
        <PasswordRules pw={p} />
        <button disabled={busy} onClick={doSetup}>
          {busy ? "Creating…" : "Create admin account"}</button>
      </div>
    );
  }

  if (screen === "forgot") {
    return (
      <div className="card auth">
        <h1 className="auth-title">Reset password</h1>
        <p className="muted">Enter your username. An administrator will be notified to
          issue you a temporary password; sign in with it and you'll be asked to set a
          new one.</p>
        <Banner msg={err} kind="error" />
        <Banner msg={info} kind="ok" />
        <input placeholder="Username" value={u} onChange={(e) => setU(e.target.value)}
               onKeyDown={(e) => e.key === "Enter" && doForgot()} />
        <button disabled={busy} onClick={doForgot}>
          {busy ? "Sending…" : "Request password reset"}</button>
        <button className="link" onClick={() => go("login")}>← Back to sign in</button>
      </div>
    );
  }

  return (
    <div className="card auth">
      <BrandHead />
      <div className="tabs">
        <button className={screen === "login" ? "tab active" : "tab"}
                onClick={() => go("login")}>Sign in</button>
        <button className={screen === "register" ? "tab active" : "tab"}
                onClick={() => go("register")}>Create account</button>
      </div>
      <Banner msg={err} kind="error" />
      <Banner msg={info} kind="ok" />
      {screen === "login" ? (
        <>
          <input placeholder="Username" value={u} onChange={(e) => setU(e.target.value)} />
          <PwInput placeholder="Password" value={p}
                   onChange={(e) => setP(e.target.value)}
                   onKeyDown={(e) => e.key === "Enter" && doLogin()} />
          {needOtp && (
            <input placeholder="6-digit code" value={otp} inputMode="numeric"
                   onChange={(e) => setOtp(e.target.value)}
                   onKeyDown={(e) => e.key === "Enter" && doLogin()} />
          )}
          <button disabled={busy} onClick={doLogin}>
            {busy ? "Signing in…" : "Sign in"}</button>
          <button className="link" onClick={() => go("forgot")}>Forgot password?</button>
        </>
      ) : (
        <>
          <input placeholder="Choose a username" value={u}
                 onChange={(e) => setU(e.target.value)} />
          <PwInput placeholder="Choose a password" value={p}
                   onChange={(e) => setP(e.target.value)}
                   onKeyDown={(e) => e.key === "Enter" && doRegister()} />
          <PasswordRules pw={p} />
          <button disabled={busy} onClick={doRegister}>
            {busy ? "Submitting…" : "Request account"}</button>
          <p className="muted small">New accounts need administrator approval before
            you can sign in.</p>
        </>
      )}
    </div>
  );
}

function ForceChangePassword({ onDone }) {
  const [p1, setP1] = useState("");
  const [p2, setP2] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit() {
    setErr("");
    if (p1 !== p2) { setErr("The two passwords don't match."); return; }
    if (p1.length < 8) { setErr("Password must be at least 8 characters."); return; }
    setBusy(true);
    try { await api.changePassword(null, p1); onDone(); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  }
  return (
    <div className="card auth">
      <h1 className="auth-title">Set a new password</h1>
      <p className="muted">You signed in with a temporary password. Choose a new password
        to finish.</p>
      <Banner msg={err} kind="error" />
      <PwInput placeholder="New password" value={p1} onChange={(e) => setP1(e.target.value)} />
      <PwInput placeholder="Confirm new password" value={p2}
               onChange={(e) => setP2(e.target.value)}
               onKeyDown={(e) => e.key === "Enter" && submit()} />
      <PasswordRules pw={p1} />
      <button disabled={busy} onClick={submit}>{busy ? "Saving…" : "Save new password"}</button>
    </div>
  );
}

// A simplified world landmass traced for the 360x180 equirectangular canvas
// (x = longitude + 180, y = 90 - latitude). It is deliberately low-detail:
// enough to recognise the continents and place a pin, not a survey map.
function MonitorPanel({ notify }) {
  const [data, setData] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const [countries, setCountries] = useState([]);
  const [range, setRange] = useState("24h");
  const [fDecision, setFDecision] = useState("");
  const [fCountry, setFCountry] = useState("");
  const [fDevice, setFDevice] = useState("");
  const [fNetwork, setFNetwork] = useState("");
  const mapRef = React.useRef(null);
  const mapObj = React.useRef(null);
  const layerRef = React.useRef(null);

  function buildQuery() {
    const p = new URLSearchParams();
    p.set("range", range);
    if (fDecision) p.set("decision", fDecision);
    if (fCountry) p.set("country", fCountry);
    if (fDevice) p.set("device", fDevice);
    if (fNetwork) p.set("network", fNetwork);
    p.set("limit", "1000");
    return p.toString();
  }

  async function refresh(quiet) {
    try {
      const d = await api.monitorHistory(buildQuery());
      if (d && d.available === false && d.reason === "history_disabled") {
        // History not set up on the server: fall back to the live snapshot.
        const live = await api.monitor(200);
        setData(live);
      } else {
        setData(d);
      }
      setLoaded(true);
    } catch (e) {
      if (!quiet) notify(e.message, "error");
      setLoaded(true);
    }
  }

  async function loadCountries() {
    try {
      const c = await api.monitorCountries();
      setCountries(c.countries || []);
    } catch {
      // Non-fatal; the country filter just stays empty.
    }
  }

  // Reload whenever a filter changes.
  useEffect(() => { refresh(false); }, [range, fDecision, fCountry, fDevice, fNetwork]);
  useEffect(() => { loadCountries(); }, []);
  // Gentle auto-refresh so the view stays current without hammering anything.
  useEffect(() => {
    const t = setInterval(() => refresh(true), 5000);
    return () => clearInterval(t);
  }, [range, fDecision, fCountry, fDevice, fNetwork]);

  function pinColour(decision) {
    if (decision === "allow") return "#3ddc97";
    if (decision === "challenge") return "#f5c542";
    return "#ff5c5c";
  }
  function networkLabel(value) {
    if (value === "datacenter") return "Datacenter / VPN";
    if (value === "direct") return "Direct";
    return cap(value || "unknown");
  }
  function networkOperator(p) {
    const org = p.asn_org || null;
    const asn = p.asn != null ? `AS${p.asn}` : null;
    if (org && asn) return `${org} (${asn})`;
    return org || asn || "Unknown network";
  }
  function placeLabel(p) {
    return [p.city, p.region, p.country].filter(Boolean).join(", ") || "Unknown location";
  }
  function accuracyLabel(km) {
    return km == null ? null : `\u00b1${km} km`;
  }

  const points = (data && data.map_points) || [];

  // Set up the Leaflet map once the container is on screen. Leaflet is bundled
  // with the app (served from our own domain, so it respects the strict CSP).
  // We still nudge the map to recalculate its size a few times because it
  // starts inside a tab that may have been hidden when it first mounted.
  useEffect(() => {
    if (!mapRef.current || mapObj.current) return;
    const map = L.map(mapRef.current, {
      worldCopyJump: true, minZoom: 1, maxZoom: 12, scrollWheelZoom: true,
    }).setView([20, 0], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "\u00a9 OpenStreetMap contributors", maxZoom: 19,
    }).addTo(map);
    mapObj.current = map;
    layerRef.current = L.layerGroup().addTo(map);
    [100, 400, 900].forEach(ms => setTimeout(() => {
      if (mapObj.current) mapObj.current.invalidateSize();
    }, ms));
    drawMarkers();
    return () => {
      if (mapObj.current) { mapObj.current.remove(); mapObj.current = null; }
    };
  }, [loaded]);

  function drawMarkers() {
    if (!mapObj.current || !layerRef.current) return;
    layerRef.current.clearLayers();
    const groups = {};
    for (const p of points) {
      if (p.lat == null || p.lon == null) continue;
      const key = `${Number(p.lat).toFixed(1)},${Number(p.lon).toFixed(1)}`;
      if (!groups[key]) groups[key] = { ...p, count: 0 };
      groups[key].count += 1;
    }
    for (const g of Object.values(groups)) {
      const r = Math.min(20, 6 + Math.log10(g.count + 1) * 6);
      const m = L.circleMarker([g.lat, g.lon], {
        radius: r, color: pinColour(g.decision), fillColor: pinColour(g.decision),
        fillOpacity: 0.55, weight: 1.5,
      });
      const acc = accuracyLabel(g.accuracy_radius_km);
      m.bindPopup(
        `<b>${placeLabel(g)}</b>${acc ? ` <span style="opacity:.7">(${acc})</span>` : ""}<br>` +
        `${networkOperator(g)}<br>${g.count} connection${g.count === 1 ? "" : "s"}`
      );
      layerRef.current.addLayer(m);
    }
  }

  // Redraw markers whenever the data changes.
  useEffect(() => { drawMarkers(); }, [data]);

  if (!loaded) {
    return (
      <div className="card"><h2>Live Monitor</h2>
        <p className="muted">Loading connection telemetry...</p></div>
    );
  }

  if (!data || (data.available === false && data.reason !== "history_disabled")) {
    const reason = (data && data.reason) || "unavailable";
    const human = {
      sentinel_not_configured: "Sentinel Gate is not configured, so there is nothing to monitor yet.",
      sentinel_unreachable: "Sentinel Gate is configured but could not be reached right now.",
      sentinel_error: "Sentinel Gate returned an error.",
      sentinel_bad_response: "Sentinel Gate sent a response we could not read.",
      telemetry_disabled: "Telemetry is disabled on the gateway.",
    }[reason] || "Live monitoring is currently unavailable.";
    return (
      <div className="card"><h2>Live Monitor <button className="ghost" onClick={() => refresh(false)}>Refresh</button></h2>
        <p className="muted">{human}</p></div>
    );
  }

  const recent = data.recent || [];
  const byDevice = data.by_device || {};
  const byNetwork = data.by_network || {};
  const topCountries = data.top_countries || data.by_country || [];
  const uniqueLocations = new Set(points.map(p => `${Number(p.lat).toFixed(1)},${Number(p.lon).toFixed(1)}`)).size;

  // by_device / by_network come as either an object (live) or a list (history).
  function asList(x) {
    if (Array.isArray(x)) return x;
    return Object.entries(x || {}).map(([label, count]) => ({ label, count }));
  }

  return (
    <div className="card">
      <h2>Live Monitor
        <button className="ghost" onClick={() => refresh(false)} style={{ marginLeft: "0.6rem" }}>Refresh</button>
        <span className="muted" style={{ fontSize: "0.8rem", marginLeft: "0.5rem" }}>Fed by Sentinel Gate</span>
      </h2>

      <div className="monitor-filters">
        <label>Range
          <select value={range} onChange={e => setRange(e.target.value)}>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="14d">Last 14 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="all">All time</option>
          </select>
        </label>
        <label>Decision
          <select value={fDecision} onChange={e => setFDecision(e.target.value)}>
            <option value="">All</option>
            <option value="allow">Allowed</option>
            <option value="challenge">Challenged</option>
            <option value="ban">Blocked</option>
          </select>
        </label>
        <label>Country
          <select value={fCountry} onChange={e => setFCountry(e.target.value)}>
            <option value="">All</option>
            {countries.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label>Device
          <select value={fDevice} onChange={e => setFDevice(e.target.value)}>
            <option value="">All</option>
            <option value="desktop">Desktop</option>
            <option value="mobile">Mobile</option>
            <option value="bot">Bot</option>
          </select>
        </label>
        <label>Network
          <select value={fNetwork} onChange={e => setFNetwork(e.target.value)}>
            <option value="">All</option>
            <option value="direct">Direct</option>
            <option value="datacenter">Datacenter / VPN</option>
          </select>
        </label>
      </div>

      <div className="monitor-stats">
        <div className="monitor-stat">
          <div className="monitor-stat-num">{data.unique_ips ?? uniqueLocations}</div>
          <div className="monitor-stat-label">Unique Clients</div>
        </div>
        <div className="monitor-stat">
          <div className="monitor-stat-num">{uniqueLocations}</div>
          <div className="monitor-stat-label">Unique Locations</div>
        </div>
        <div className="monitor-stat">
          <div className="monitor-stat-num">{data.total_connections ?? 0}</div>
          <div className="monitor-stat-label">Total Requests</div>
        </div>
      </div>

      <div ref={mapRef} className="monitor-leaflet" />
      <div className="monitor-legend">
        <span><i style={{ background: "#3ddc97" }} /> Allowed</span>
        <span><i style={{ background: "#f5c542" }} /> Challenged</span>
        <span><i style={{ background: "#ff5c5c" }} /> Blocked</span>
      </div>

      <div className="monitor-breakdowns">
        <div className="monitor-break">
          <h3>Device</h3>
          {asList(byDevice).length === 0 && <span className="muted">No data</span>}
          {asList(byDevice).map(d => (
            <div key={d.label} className="monitor-break-row"><span>{cap(d.label)}</span><span className="tag">{d.count}</span></div>
          ))}
        </div>
        <div className="monitor-break">
          <h3>Network</h3>
          {asList(byNetwork).length === 0 && <span className="muted">No data</span>}
          {asList(byNetwork).map(n => (
            <div key={n.label} className="monitor-break-row"><span>{networkLabel(n.label)}</span><span className="tag">{n.count}</span></div>
          ))}
        </div>
        <div className="monitor-break">
          <h3>Top Countries</h3>
          {asList(topCountries).length === 0 && <span className="muted">No data</span>}
          {asList(topCountries).map(c => (
            <div key={c.label} className="monitor-break-row"><span>{cap(c.label)}</span><span className="tag">{c.count}</span></div>
          ))}
        </div>
      </div>

      <h3 style={{ marginTop: "1rem" }}>Recent Connections</h3>
      <table>
        <thead>
          <tr><th>Time</th><th>Location</th><th>Network Operator</th><th>Device</th><th>Type</th><th>Decision</th></tr>
        </thead>
        <tbody>
          {recent.length === 0 && <tr><td colSpan="6" className="muted">No connections match these filters.</td></tr>}
          {recent.slice(0, 50).map((r, i) => {
            const acc = accuracyLabel(r.accuracy_radius_km);
            return (
              <tr key={i}>
                <td>{(r.ts_iso || r.ts || "").replace("T", " ").replace("Z", "")}</td>
                <td>{placeLabel(r)}{acc && <span className="muted monitor-acc">{acc}</span>}</td>
                <td>{networkOperator(r)}{r.reverse_dns && <span className="muted monitor-rdns">{r.reverse_dns}</span>}</td>
                <td>{cap(r.device_type || "Unknown")}</td>
                <td>{networkLabel(r.network_type)}</td>
                <td><span className={`tag ${r.decision === "allow" ? "" : "danger"}`}>{cap(r.decision || "?")}</span></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="muted" style={{ fontSize: "0.78rem", marginTop: "0.5rem" }}>
        Location comes from the connecting IP address, so it is accurate to roughly a city, not a street. The plus or minus figure is the location database's own confidence radius. "Datacenter / VPN" flags known hosting ranges and is a best-effort signal: a residential VPN can still look like a direct connection. The network operator and reverse DNS are exact. None of these signals is used to allow or block a request; they are here for visibility only.
      </p>
    </div>
  );
}

function SigningFingerprint({ publicKey, algorithm }) {
  const [fp, setFp] = useState("");
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        // Decode base64 public key and hash it with SHA-256 in the browser,
        // matching the fingerprint the CLI prints on 'qcg trust'.
        const raw = Uint8Array.from(atob(publicKey), (c) => c.charCodeAt(0));
        const digest = await crypto.subtle.digest("SHA-256", raw);
        const hex = Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, "0")).join("");
        if (alive) setFp(hex);
      } catch { if (alive) setFp("(unavailable)"); }
    })();
    return () => { alive = false; };
  }, [publicKey]);

  async function copyFp() {
    try { await navigator.clipboard.writeText(`sha256:${fp}`); } catch { /* ignore */ }
  }

  return (
    <div className="fingerprint">
      <span className="fingerprint-alg">{algorithm}</span>
      <code className="fingerprint-hex">sha256:{fp || "…"}</code>
      {fp && <button className="ghost" onClick={copyFp}>Copy</button>}
    </div>
  );
}

function KeysPanel({ notify }) {
  const [keys, setKeys] = useState([]);
  const [name, setName] = useState("");
  const [filter, setFilter] = useState("");
  const [signing, setSigning] = useState(null);

  async function refresh() {
    try { setKeys((await api.listKeys()).keys); } catch (e) { notify(e.message, "error"); }
  }
  async function loadSigning() {
    try { setSigning(await api.signingKey()); } catch { /* no identity: leave unset */ }
  }
  useEffect(() => { refresh(); loadSigning(); }, []);

  async function gen() {
    if (!name) return;
    try { await api.generateKey(name); setName(""); notify(`Key “${name}” created`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function rotate(n) {
    try { const r = await api.rotateKey(n); notify(`“${n}” rotated to v${r.version}`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function del(n) {
    try { await api.deleteKey(n); notify(`“${n}” deleted`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }

  return (
    <div className="card">
      <h2>Keys</h2>
      <div className="row">
        <input placeholder="New key name (e.g. app-data)" value={name}
               onChange={(e) => setName(e.target.value)}
               onKeyDown={(e) => e.key === "Enter" && gen()} />
        <button onClick={gen}>Generate ML-KEM-1024</button>
      </div>
      {keys.length > 0 && (
        <input className="search" placeholder="Search keys by name…" value={filter}
               onChange={(e) => setFilter(e.target.value)} />
      )}
      <table>
        <thead><tr><th>Name</th><th>Version</th><th>Algorithm</th><th>State</th><th></th></tr></thead>
        <tbody>
          {keys.length === 0 && <tr><td colSpan="5" className="muted">No keys yet.</td></tr>}
          {(() => {
            const shown = keys.filter((k) =>
              k.name.toLowerCase().includes(filter.trim().toLowerCase()));
            if (keys.length > 0 && shown.length === 0) {
              return <tr><td colSpan="5" className="muted">No keys match “{filter}”.</td></tr>;
            }
            return shown.map((k) => (
              <tr key={`${k.name}-${k.version}`}>
                <td>{k.name}</td><td>v{k.version}</td><td>{k.algorithm}</td>
                <td>{k.active ? <span className="tag">active</span> : <span className="muted">old</span>}</td>
                <td className="actions">
                  {k.active && <button className="ghost" onClick={() => rotate(k.name)}>Rotate</button>}
                  {k.active && <button className="ghost danger" onClick={() => del(k.name)}>Delete</button>}
                </td>
              </tr>
            ));
          })()}
        </tbody>
      </table>
      {signing && (
        <div className="authenticity">
          <h3>Public-Key Authenticity</h3>
          <p className="muted">
            This KMS signs every public key it serves with its {signing.algorithm} identity,
            so clients can verify a recipient key genuinely came from here and was not
            substituted in transit. Share this fingerprint with users so they can confirm
            it when they run <code>qcg trust</code>.
          </p>
          <SigningFingerprint publicKey={signing.public_key} algorithm={signing.algorithm} />
        </div>
      )}
    </div>
  );
}

function PerformancePanel({ notify }) {
  const [keys, setKeys] = useState([]);
  const [key, setKey] = useState("");
  const [sample, setSample] = useState("");
  const [iterations, setIterations] = useState(20);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);

  useEffect(() => {
    api.listKeys()
      .then((r) => {
        const active = (r.keys || []).filter((k) => k.active);
        setKeys(active);
        if (active[0]) setKey(active[0].name);
      })
      .catch(() => {});
  }, []);

  function stats(arr) {
    if (!arr.length) return { min: null, avg: null, max: null };
    const valid = arr.filter((v) => v != null);
    if (!valid.length) return { min: null, avg: null, max: null };
    const sum = valid.reduce((a, b) => a + b, 0);
    return { min: Math.min(...valid), avg: sum / valid.length, max: Math.max(...valid) };
  }

  async function run() {
    if (!key) { notify("Select a key first (create one in the Keys panel).", "error"); return; }
    const n = Math.max(1, Math.min(200, Number(iterations) || 1));
    const payload = sample || "qcg benchmark payload";
    setBusy(true); setResult(null); setProgress(0);
    const encServer = [], encRound = [], decServer = [], decRound = [];
    try {
      // One warm-up cycle (discarded) so cold-start cost doesn't skew the stats.
      const warm = await api.encrypt(key, payload, "");
      await api.decrypt(warm, "");

      for (let i = 0; i < n; i++) {
        const t0 = performance.now();
        const env = await api.encrypt(key, payload, "");
        encRound.push(performance.now() - t0);
        encServer.push(env.timing_ms);

        const t1 = performance.now();
        const dec = await api.decrypt(env, "");
        decRound.push(performance.now() - t1);
        decServer.push(dec.timing_ms);

        setProgress(i + 1);
      }
      setResult({
        n,
        encServer: stats(encServer), encRound: stats(encRound),
        decServer: stats(decServer), decRound: stats(decRound),
      });
      notify(`Benchmark complete (${n} iterations)`, "ok");
    } catch (e) { notify(e.message, "error"); }
    finally { setBusy(false); }
  }

  const fmt = (v) => (v == null ? "-" : `${Number(v).toFixed(3)}`);
  const cell = (s) => (
    <>
      <td className="num">{fmt(s.min)}</td>
      <td className="num">{fmt(s.avg)}</td>
      <td className="num">{fmt(s.max)}</td>
    </>
  );

  return (
    <div className="card">
      <h2>Encryption Performance</h2>
      <div className="row wrap">
        <select value={key} onChange={(e) => setKey(e.target.value)}>
          {keys.length === 0 && <option value="">No keys yet</option>}
          {keys.map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
        </select>
        <input placeholder="Sample text (optional)" value={sample}
               onChange={(e) => setSample(e.target.value)} />
        <select value={iterations} onChange={(e) => setIterations(Number(e.target.value))}>
          {[10, 20, 50, 100].map((v) => <option key={v} value={v}>{v} iterations</option>)}
        </select>
        <button onClick={run} disabled={busy}>
          {busy ? `Measuring… ${progress}/${iterations}` : "Run benchmark"}</button>
      </div>
      {result && (
        <table className="bench">
          <thead>
            <tr><th rowSpan="2">Operation ({result.n} runs)</th>
                <th colSpan="3">Server crypto (ms)</th>
                <th colSpan="3">Round-trip (ms)</th></tr>
            <tr><th className="num">min</th><th className="num">avg</th><th className="num">max</th>
                <th className="num">min</th><th className="num">avg</th><th className="num">max</th></tr>
          </thead>
          <tbody>
            <tr><td>Encryption (encapsulate + AES-GCM)</td>
                {cell(result.encServer)}{cell(result.encRound)}</tr>
            <tr><td>Decryption (decapsulate + AES-GCM)</td>
                {cell(result.decServer)}{cell(result.decRound)}</tr>
          </tbody>
        </table>
      )}
    </div>
  );
}

function ApiKeysPanel({ notify }) {
  const [items, setItems] = useState([]);
  const [label, setLabel] = useState("");
  const [fresh, setFresh] = useState("");

  async function refresh() {
    try { setItems((await api.listApiKeys()).api_keys); } catch (e) { notify(e.message, "error"); }
  }
  useEffect(() => { refresh(); }, []);

  async function create() {
    if (!label) return;
    try {
      const r = await api.createApiKey(label);
      setFresh(r.api_key); setLabel(""); refresh();
      notify("API key created. Copy it now, it won't be shown again", "ok");
    } catch (e) { notify(e.message, "error"); }
  }
  async function del(l) {
    try { await api.deleteApiKey(l); refresh(); notify(`“${l}” revoked`, "ok"); }
    catch (e) { notify(e.message, "error"); }
  }

  return (
    <div className="card">
      <h2>API Keys</h2>
      <div className="row">
        <input placeholder="Label (e.g. ci-pipeline)" value={label}
               onChange={(e) => setLabel(e.target.value)}
               onKeyDown={(e) => e.key === "Enter" && create()} />
        <button onClick={create}>Create</button>
      </div>
      {fresh && (
        <div className="banner ok">
          <code className="token">{fresh}</code>
          <div className="muted">Store this securely. It is shown only once.</div>
        </div>
      )}
      <table>
        <thead><tr><th>Label</th><th>Created</th><th>Last used</th><th></th></tr></thead>
        <tbody>
          {items.length === 0 && <tr><td colSpan="4" className="muted">No API keys.</td></tr>}
          {items.map((k) => (
            <tr key={k.label}>
              <td>{k.label}</td>
              <td>{new Date(k.created_at * 1000).toLocaleString()}</td>
              <td>{k.last_used_at ? new Date(k.last_used_at * 1000).toLocaleString() : "-"}</td>
              <td className="actions">
                <button className="ghost danger" onClick={() => del(k.label)}>Revoke</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function fmtSecs(s) {
  if (s % 3600 === 0) return `${s / 3600} h`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

// Display-only: capitalize the first letter (value sent to the API stays lowercase).
function cap(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function EmployeesPanel({ notify }) {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [defTtl, setDefTtl] = useState(0);
  const [nu, setNu] = useState("");
  const [np, setNp] = useState("");
  const [nr, setNr] = useState("");
  const [nadmin, setNadmin] = useState(false);
  const [freshKey, setFreshKey] = useState("");
  const [allKeys, setAllKeys] = useState([]);
  const [grantsByUser, setGrantsByUser] = useState({});
  const [grantSel, setGrantSel] = useState({});
  const [empFilter, setEmpFilter] = useState("");

  async function refresh() {
    try {
      const r = await api.listRoles();
      setRoles(r.roles); setDefTtl(r.default_ttl_seconds);
      if (!nr && r.roles.length) setNr(r.roles[0].role);
      setUsers((await api.listUsers()).users.filter((u) => u.status === "active"));
      // unique key names (one key can have several versions)
      const keyNames = [...new Set(((await api.listKeys()).keys || []).map((k) => k.name))];
      setAllKeys(keyNames);
      // build username -> [keys] by inverting each key's grant list
      const byUser = {};
      for (const kn of keyNames) {
        try {
          const g = await api.listGrants(kn);
          for (const un of (g.users || [])) (byUser[un] = byUser[un] || []).push(kn);
        } catch { /* ignore a single key's grant fetch */ }
      }
      setGrantsByUser(byUser);
    } catch (e) { notify(e.message, "error"); }
  }
  useEffect(() => { refresh(); }, []);

  async function create() {
    if (!nu || !np) { notify("username and password required", "error"); return; }
    try {
      await api.createUser(nu, np, nadmin ? "admin" : nr, nadmin);
      notify(`Employee “${nu}” created`, "ok");
      setNu(""); setNp(""); setNadmin(false); refresh();
    } catch (e) { notify(e.message, "error"); }
  }
  async function setRole(username, role) {
    try { await api.changeRole(username, role); notify(`${username} → ${role}`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function remove(username) {
    if (!confirm(`Delete ${username}? This also removes their keys and grants.`)) return;
    try { await api.deleteUser(username); notify(`${username} deleted`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function issueKey(username) {
    try {
      const r = await api.createApiKey(`${username}-laptop`, username);
      setFreshKey(`${username}: ${r.api_key}`);
      notify("Access key generated. Copy it now, shown once", "ok");
    } catch (e) { notify(e.message, "error"); }
  }
  async function grant(username) {
    const key = grantSel[username] || "";
    if (!key) { notify("Pick a key to grant first", "error"); return; }
    try {
      await api.grantKey(key, username);
      notify(`${username} granted access to “${key}”`, "ok");
      setGrantSel((s) => ({ ...s, [username]: "" }));
      refresh();
    } catch (e) { notify(e.message, "error"); }
  }
  async function revoke(username, key) {
    try {
      await api.revokeKey(key, username);
      notify(`${username}'s access to “${key}” revoked`, "ok");
      refresh();
    } catch (e) { notify(e.message, "error"); }
  }

  return (
    <div className="card">
      <h2>Employees</h2>
      <p className="muted">
        A user’s role sets their decryption window. Windows:&nbsp;
        {roles.map((r) => <span key={r.role} className="tag">{cap(r.role)}&nbsp;{fmtSecs(r.ttl_seconds)}</span>)}
        <span className="tag">others {fmtSecs(defTtl)}</span>
      </p>

      <div className="row wrap">
        <input placeholder="Employee ID / username" value={nu} onChange={(e) => setNu(e.target.value)} />
        <input type="password" placeholder="Temp password" value={np} onChange={(e) => setNp(e.target.value)} />
        <select value={nadmin ? "admin" : nr} disabled={nadmin} onChange={(e) => setNr(e.target.value)}>
          {roles.map((r) => <option key={r.role} value={r.role}>{cap(r.role)}</option>)}
        </select>
        <label className="check"><input type="checkbox" checked={nadmin}
          onChange={(e) => setNadmin(e.target.checked)} /> Admin</label>
        <button onClick={create}>Add employee</button>
      </div>

      {freshKey && (
        <div className="banner ok">
          <code className="token">{freshKey}</code>
          <div className="muted">Install on that employee’s device. Shown only once.</div>
        </div>
      )}

      {users.length > 0 && (
        <input className="search" placeholder="Search employees by username…" value={empFilter}
               onChange={(e) => setEmpFilter(e.target.value)} />
      )}

      <table>
        <thead><tr><th>Username</th><th>Role / window</th><th>Key access</th><th>MFA</th><th>Actions</th></tr></thead>
        <tbody>
          {users.length === 0 && <tr><td colSpan="5" className="muted">No employees yet.</td></tr>}
          {users.filter((u) => u.username.toLowerCase().includes(empFilter.trim().toLowerCase())).map((u) => {
            const ttl = u.is_admin ? null : (roles.find((r) => r.role === u.role)?.ttl_seconds ?? defTtl);
            return (
              <tr key={u.username}>
                <td>{u.username}{u.is_admin && <span className="tag">Admin</span>}</td>
                <td>
                  {u.is_admin ? <span className="muted">Admin tier</span> : (
                    <select value={u.role} onChange={(e) => setRole(u.username, e.target.value)}>
                      {roles.map((r) => <option key={r.role} value={r.role}>{cap(r.role)}</option>)}
                      {!roles.find((r) => r.role === u.role) && <option value={u.role}>{cap(u.role)}</option>}
                    </select>
                  )}
                  {ttl != null && <span className="muted">&nbsp;{fmtSecs(ttl)}</span>}
                </td>
                <td>
                  {u.is_admin ? <span className="muted">all keys</span> : (
                    <div className="grants">
                      {(grantsByUser[u.username] || []).map((kn) => (
                        <span key={kn} className="tag grant-chip">
                          {kn}
                          <button className="chip-x" title="Revoke access"
                                  onClick={() => revoke(u.username, kn)}>×</button>
                        </span>
                      ))}
                      {(grantsByUser[u.username] || []).length === 0 &&
                        <span className="muted">none</span>}
                      <span className="grant-add">
                        <select value={grantSel[u.username] || ""}
                                onChange={(e) => setGrantSel((s) => ({ ...s, [u.username]: e.target.value }))}>
                          <option value="">Select a key…</option>
                          {allKeys
                            .filter((kn) => !(grantsByUser[u.username] || []).includes(kn))
                            .map((kn) => <option key={kn} value={kn}>{kn}</option>)}
                        </select>
                        <button className="ghost" onClick={() => grant(u.username)}>Grant</button>
                      </span>
                    </div>
                  )}
                </td>
                <td>{u.mfa_enabled ? <span className="tag">on</span> : <span className="muted">off</span>}</td>
                <td className="actions">
                  <button className="ghost" onClick={() => issueKey(u.username)}>Generate Access Key</button>
                  {!u.is_admin && <button className="ghost danger" onClick={() => remove(u.username)}>Delete</button>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ActiveCheckoutsPanel({ notify }) {
  const [leases, setLeases] = useState([]);
  const [intact, setIntact] = useState(null);

  async function refresh() {
    try {
      setLeases((await api.listLeases()).leases);
      setIntact((await api.auditVerify()).intact);
    } catch (e) { notify(e.message, "error"); }
  }
  useEffect(() => { refresh(); const t = setInterval(refresh, 15000); return () => clearInterval(t); }, []);

  return (
    <div className="card">
      <h2>Active Checkouts <button className="ghost" onClick={refresh}>↻</button>
        {intact != null && <span className={`tag ${intact ? "" : "danger"}`}>
          audit {intact ? "intact" : "TAMPERED"}</span>}
      </h2>
      <table>
        <thead><tr><th>User</th><th>Key</th><th>Expires</th></tr></thead>
        <tbody>
          {leases.length === 0 && <tr><td colSpan="3" className="muted">No keys checked out right now.</td></tr>}
          {leases.map((l) => (
            <tr key={l.id}>
              <td>{l.username}</td><td>{l.key_name}</td>
              <td>{new Date(l.expires_at * 1000).toLocaleTimeString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AccountRequestsPanel({ notify }) {
  const [users, setUsers] = useState([]);
  const [temp, setTemp] = useState("");
  async function refresh() {
    try { setUsers((await api.listUsers()).users); }
    catch (e) { notify(e.message, "error"); }
  }
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const pending = users.filter((u) => u.status === "pending");
  const resets = users.filter((u) => u.reset_requested);

  async function approve(name) {
    try { await api.approveUser(name); notify(`${name} approved, they can sign in now`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function decline(name) {
    if (!confirm(`Decline and delete the request from “${name}”? They will not be able to sign in.`)) return;
    try { await api.deleteUser(name); notify(`${name}'s request declined`, "ok"); refresh(); }
    catch (e) { notify(e.message, "error"); }
  }
  async function issueTemp(name) {
    try {
      const r = await api.resetPassword(name);
      setTemp(`${name} → ${r.temp_password}`);
      notify(`Temporary password issued for ${name}`, "ok");
      refresh();
    } catch (e) { notify(e.message, "error"); }
  }

  return (
    <section className="card">
      <h2>Account Requests</h2>
      {temp && (
        <div className="banner ok">
          Temporary password (share securely, shown once):&nbsp;
          <span className="token">{temp}</span>. The user must set a new password at next sign-in.
        </div>
      )}
      {pending.length === 0 && resets.length === 0 && !temp &&
        <p className="muted">No pending account or password requests.</p>}

      {pending.length > 0 && (
        <>
          <h3 className="sub">New account requests</h3>
          <table className="grid">
            <thead><tr><th>Username</th><th>Requested</th><th>Actions</th></tr></thead>
            <tbody>
              {pending.map((u) => (
                <tr key={u.username}>
                  <td>{u.username}</td>
                  <td className="muted">{new Date(u.created_at * 1000).toLocaleString()}</td>
                  <td className="actions">
                    <button onClick={() => approve(u.username)}>Approve</button>
                    <button className="ghost danger" onClick={() => decline(u.username)}>Decline</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {resets.length > 0 && (
        <>
          <h3 className="sub">Password reset requests</h3>
          <table className="grid">
            <thead><tr><th>Username</th><th>Actions</th></tr></thead>
            <tbody>
              {resets.map((u) => (
                <tr key={u.username}>
                  <td>{u.username}</td>
                  <td className="actions">
                    <button onClick={() => issueTemp(u.username)}>Generate temp password</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

function SecurityPanel({ notify, mfaOn, onMfaChange }) {
  const [enroll, setEnroll] = useState(null);
  const [qr, setQr] = useState("");
  const [otp, setOtp] = useState("");
  const [cur, setCur] = useState("");
  const [np, setNp] = useState("");

  useEffect(() => {
    if (enroll && enroll.provisioning_uri) {
      QRCode.toDataURL(enroll.provisioning_uri, { width: 192, margin: 1 })
        .then(setQr).catch(() => setQr(""));
    } else {
      setQr("");
    }
  }, [enroll]);

  async function startEnroll() {
    try { setEnroll(await api.mfaEnroll()); }
    catch (e) { notify(e.message, "error"); }
  }
  async function activate() {
    try {
      await api.mfaActivate(otp);
      notify("Two-factor authentication enabled", "ok");
      setEnroll(null); setOtp(""); onMfaChange(true);
    } catch (e) { notify(e.message, "error"); }
  }
  async function changePw() {
    if (np.length < 8) { notify("New password must be at least 8 characters", "error"); return; }
    try { await api.changePassword(cur, np); notify("Password changed", "ok"); setCur(""); setNp(""); }
    catch (e) { notify(e.message, "error"); }
  }

  return (
    <section className="card">
      <h2>Security</h2>
      <div className="sec-grid">
        <div>
          <h3 className="sub">Two-factor authentication</h3>
          {mfaOn ? (
            <p className="muted"><span className="tag">Enabled</span>&nbsp; A 6-digit code is
              required at every sign-in.</p>
          ) : enroll ? (
            <div className="col">
              <p className="muted small">Scan this with an authenticator app (Google
                Authenticator, Authy, 1Password…), or enter the secret manually, then
                type a 6-digit code to confirm.</p>
              {qr && <img className="qr" src={qr} alt="Scan to add to authenticator" />}
              <div className="mfa-secret">Secret:&nbsp;<span className="token">{enroll.secret}</span></div>
              <details>
                <summary className="muted small">Show setup link (otpauth://)</summary>
                <div className="token wrap">{enroll.provisioning_uri}</div>
              </details>
              <div className="row">
                <input placeholder="6-digit code" inputMode="numeric" value={otp}
                       onChange={(e) => setOtp(e.target.value)} />
                <button onClick={activate}>Confirm &amp; enable</button>
              </div>
            </div>
          ) : (
            <button onClick={startEnroll}>Enable two-factor</button>
          )}
        </div>
        <div>
          <h3 className="sub">Change password</h3>
          <div className="col">
            <PwInput placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} />
            <PwInput placeholder="New password" value={np} onChange={(e) => setNp(e.target.value)} />
            <PasswordRules pw={np} />
            <button onClick={changePw}>Update password</button>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(false);
  const [principal, setPrincipal] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [view, setView] = useState("console");
  const [mfaOn, setMfaOn] = useState(false);
  const [mustChange, setMustChange] = useState(false);
  const [note, setNote] = useState({ msg: "", kind: "info" });

  async function loadMe() {
    const r = await api.me();
    setPrincipal(r.principal); setIsAdmin(!!r.is_admin);
    setMfaOn(!!r.mfa); setMustChange(!!r.must_change_password);
    setAuthed(true);
  }

  // The session cookie has no expiry, so the browser drops it when the browser
  // is fully closed; the next visit then requires a fresh sign-in. While the
  // browser stays open, the session persists across tabs and refreshes.
  useEffect(() => { loadMe().catch(() => {}); }, []);

  function notify(msg, kind) {
    setNote({ msg, kind });
    setTimeout(() => setNote({ msg: "", kind: "info" }), 4000);
  }

  async function afterAuth() { try { await loadMe(); } catch { /* ignore */ } }
  async function logout() {
    try { await api.logout(); } catch { /* ignore */ }
    setAuthed(false); setMustChange(false);
  }

  if (!authed) return <div className="shell center"><AuthGate onAuthed={afterAuth} /></div>;
  if (mustChange) {
    return (
      <div className="shell center">
        <ForceChangePassword onDone={() => loadMe().catch(() => {})} />
      </div>
    );
  }

  return (
    <div className="shell">
      <header>
        <div className="brand">
          <img src="/logo.png" alt="" className="brand-logo"
               onError={(e) => { e.currentTarget.style.display = "none"; }} />
          <span className="brand-name">Quantum Cloud Guard</span>
          <span className="muted brand-sub">Key Management Service</span>
        </div>
        <div className="who">
          <span className="muted">{principal}{isAdmin && " · Admin"}</span>
          <button className="ghost" onClick={logout}>Sign out</button>
        </div>
      </header>
      <Banner msg={note.msg} kind={note.kind} />
      {isAdmin && (
        <nav className="viewnav">
          <button className={view === "console" ? "tab active" : "tab"}
                  onClick={() => setView("console")}>Console</button>
          <button className={view === "monitor" ? "tab active" : "tab"}
                  onClick={() => setView("monitor")}>Live Monitor</button>
        </nav>
      )}
      <main>
        {isAdmin && view === "monitor" && <MonitorPanel notify={notify} />}
        {(!isAdmin || view === "console") && <>
          {isAdmin && <AccountRequestsPanel notify={notify} />}
          {isAdmin && <EmployeesPanel notify={notify} />}
          {isAdmin && <ActiveCheckoutsPanel notify={notify} />}
          <KeysPanel notify={notify} />
          <PerformancePanel notify={notify} />
          <ApiKeysPanel notify={notify} />
          <SecurityPanel notify={notify} mfaOn={mfaOn} onMfaChange={setMfaOn} />
        </>}
      </main>
    </div>
  );
}
