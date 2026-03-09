import { useState, useEffect, useCallback } from "react";
import axios from "axios";

const API = "http://localhost:5000/api";

function verdictChip(verdict) {
  const map = {
    SAFE:  { bg: "#d1fae5", color: "#065f46", label: "Safe"    },
    WARN:  { bg: "#fef3c7", color: "#92400e", label: "Warning" },
    BLOCK: { bg: "#fee2e2", color: "#991b1b", label: "Blocked" },
  };
  const s = map[verdict] ?? map.SAFE;
  return (
    <span style={{ background: s.bg, color: s.color, padding: "3px 10px", borderRadius: 99, fontSize: 12, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase" }}>
      {s.label}
    </span>
  );
}

function ThreatBar({ score }) {
  const pct = Math.round((score ?? 0) * 100);
  const color = pct < 30 ? "#10b981" : pct < 60 ? "#f59e0b" : "#ef4444";
  return (
    <div style={{ marginTop: 4 }}>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, color:"#6b7280", marginBottom:4 }}>
        <span>Threat score</span>
        <span style={{ color, fontWeight:700 }}>{pct}/100</span>
      </div>
      <div style={{ background:"#f3f4f6", borderRadius:99, height:8, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:color, borderRadius:99, transition:"width 0.6s cubic-bezier(.4,0,.2,1)" }} />
      </div>
    </div>
  );
}

function MiniBarChart({ data }) {
  if (!data?.length) return null;
  const max = Math.max(...data.map(d => d.clicks), 1);
  return (
    <div style={{ display:"flex", alignItems:"flex-end", gap:4, height:56 }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:2 }}>
          <div style={{ width:"100%", background: d.clicks > 0 ? "#6366f1" : "#e5e7eb", borderRadius:"3px 3px 0 0", height:`${Math.max(4, (d.clicks / max) * 48)}px`, transition:"height 0.4s ease" }} />
          <span style={{ fontSize:9, color:"#9ca3af", whiteSpace:"nowrap" }}>{d.date.split(" ")[1]}</span>
        </div>
      ))}
    </div>
  );
}

function Modal({ title, children, onClose }) {
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.45)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:1000, padding:24 }}>
      <div style={{ background:"#fff", borderRadius:16, padding:32, maxWidth:440, width:"100%", boxShadow:"0 25px 60px rgba(0,0,0,0.25)" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
          <h3 style={{ margin:0, fontSize:18, fontWeight:700, color:"#111827" }}>{title}</h3>
          <button onClick={onClose} style={{ background:"none", border:"none", cursor:"pointer", fontSize:22, color:"#9ca3af", lineHeight:1, padding:0 }}>×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

// Props: shortCode (string), onBack (function)
export default function URLDetailPage({ shortCode, onBack }) {
  // token stored under -linkfort_token- by AuthContext; some older code may use "access_token"
  const token = localStorage.getItem("linkfort_token") || localStorage.getItem("access_token") || localStorage.getItem("token");

  const [url, setUrl] = useState(null);
  const [clicks, setClicks] = useState([]);
  const [trend, setTrend] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showEdit, setShowEdit] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [editDays, setEditDays] = useState("");
  const [noExpiry, setNoExpiry] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [toast, setToast] = useState(null);

  const fetchDetail = useCallback(async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API}/urls/${shortCode}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUrl(res.data.data);
      setClicks(res.data.recent_clicks ?? []);
      setTrend(res.data.click_trend ?? []);
    } catch (err) {
      setError(err.response?.data?.error ?? "Failed to load URL details");
    } finally {
      setLoading(false);
    }
  }, [shortCode, token]);

  useEffect(() => { fetchDetail(); }, [fetchDetail]);

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const copyShortUrl = () => {
    navigator.clipboard.writeText(url.short_url);
    showToast("Copied to clipboard!");
  };

  const handleToggle = async () => {
    try {
      const res = await axios.patch(`${API}/urls/${shortCode}/toggle`, {}, { headers: { Authorization: `Bearer ${token}` } });
      setUrl(res.data.data);
      showToast(res.data.message);
    } catch (err) {
      showToast(err.response?.data?.error ?? "Failed to update", "error");
    }
  };

  const handleEdit = async () => {
    setSaving(true);
    try {
      const res = await axios.patch(`${API}/urls/${shortCode}`, { expiration_days: noExpiry ? null : parseInt(editDays) }, { headers: { Authorization: `Bearer ${token}` } });
      setUrl(res.data.data);
      setShowEdit(false);
      showToast("Expiration updated!");
    } catch (err) {
      showToast(err.response?.data?.error ?? "Failed to update", "error");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await axios.delete(`${API}/urls/${shortCode}`, { headers: { Authorization: `Bearer ${token}` } });
      showToast("URL deleted");
      setTimeout(() => onBack(), 1200);
    } catch (err) {
      showToast(err.response?.data?.error ?? "Failed to delete", "error");
      setDeleting(false);
      setShowDelete(false);
    }
  };

  const openEdit = () => {
    if (url.expires_at) {
      const days = Math.ceil((new Date(url.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
      setEditDays(Math.max(1, days).toString());
      setNoExpiry(false);
    } else {
      setEditDays("30");
      setNoExpiry(false);
    }
    setShowEdit(true);
  };

  if (loading) return (
    <div style={S.centered}><div style={S.spinner} /></div>
  );

  if (error) return (
    <div style={S.centered}>
      <div style={S.errorBox}>
        <span style={{ fontSize:40 }}>🔍</span>
        <h2 style={{ color:"#ef4444", margin:"12px 0 8px" }}>URL Not Found</h2>
        <p style={{ color:"#6b7280", margin:"0 0 20px" }}>{error}</p>
        <button onClick={onBack} style={S.btnPrimary}>← Back to Dashboard</button>
      </div>
    </div>
  );

  const isExpired = url.is_expired;
  const isDisabled = !url.is_active;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500&display=swap');
        @keyframes spin { to { transform:rotate(360deg) } }
        @keyframes slideUp { from { transform:translateY(10px);opacity:0 } to { transform:translateY(0);opacity:1 } }
      `}</style>

      {toast && (
        <div style={{ position:"fixed", top:20, right:20, zIndex:2000, background: toast.type==="error" ? "#ef4444" : "#10b981", color:"#fff", padding:"12px 20px", borderRadius:10, fontWeight:600, fontSize:14, boxShadow:"0 8px 24px rgba(0,0,0,0.2)", animation:"slideUp 0.2s ease" }}>
          {toast.type === "error" ? "❌" : "✅"} {toast.msg}
        </div>
      )}

      <div style={{ maxWidth:900, margin:"0 auto", padding:"24px 20px", fontFamily:"'DM Sans',sans-serif" }}>

        <button onClick={onBack} style={S.backBtn}>← Back to Dashboard</button>

        {/* Header */}
        <div style={S.header}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap", marginBottom:6 }}>
              <h1 style={S.title}>/{url.short_code}</h1>
              {verdictChip(url.threat_verdict)}
              {isExpired  && <span style={{ ...S.badge, background:"#e5e7eb", color:"#374151" }}>Expired</span>}
              {isDisabled && <span style={{ ...S.badge, background:"#fef2f2", color:"#b91c1c" }}>Disabled</span>}
            </div>
            <p style={S.originalUrl}>{url.original_url}</p>
          </div>
          <div style={{ display:"flex", gap:10, flexWrap:"wrap", alignSelf:"flex-start" }}>
            <button onClick={copyShortUrl} style={S.btnOutline}>📋 Copy</button>
            <button onClick={openEdit} style={S.btnOutline}>✏️ Edit</button>
            <button onClick={handleToggle} style={{ ...S.btnOutline, color: isDisabled ? "#10b981" : "#f59e0b", borderColor: isDisabled ? "#10b981" : "#f59e0b" }}>
              {isDisabled ? "✅ Enable" : "⏸ Disable"}
            </button>
            <button onClick={() => setShowDelete(true)} style={{ ...S.btnOutline, color:"#ef4444", borderColor:"#ef4444" }}>🗑 Delete</button>
          </div>
        </div>

        {/* Stats */}
        <div style={S.statsRow}>
          {[
            { label:"Total Clicks", value: url.click_count, icon:"👆" },
            { label:"Created", value: new Date(url.created_at).toLocaleDateString("en-GB",{day:"numeric",month:"short",year:"numeric"}), icon:"📅" },
            { label:"Expires", value: url.expires_at ? new Date(url.expires_at).toLocaleDateString("en-GB",{day:"numeric",month:"short",year:"numeric"}) : "Never", icon:"⏰" },
            { label:"Threat Score", value: `${Math.round((url.threat_score??0)*100)}/100`, icon:"🛡️" }
          ].map((s,i) => (
            <div key={i} style={S.statCard}>
              <span style={{ fontSize:24 }}>{s.icon}</span>
              <div>
                <div style={{ fontSize:20, fontWeight:800, color:"#111827", fontFamily:"Syne,sans-serif" }}>{s.value}</div>
                <div style={{ fontSize:12, color:"#9ca3af", marginTop:2 }}>{s.label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Two col */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, marginBottom:20 }}>
          <div style={S.card}>
            <h3 style={S.cardTitle}>🛡️ Threat Analysis</h3>
            <ThreatBar score={url.threat_score} />
            {url.threat_details?.all_reasons?.length > 0
              ? <ul style={{ margin:"16px 0 0", padding:"0 0 0 18px" }}>{url.threat_details.all_reasons.map((r,i) => <li key={i} style={{ fontSize:13, color:"#374151", marginBottom:6, lineHeight:"1.5" }}>{r}</li>)}</ul>
              : <p style={{ fontSize:13, color:"#6b7280", marginTop:12 }}>No threats detected.</p>
            }
          </div>
          <div style={S.card}>
            <h3 style={S.cardTitle}>📈 Click Trend (7 days)</h3>
            <MiniBarChart data={trend} />
            <p style={{ fontSize:12, color:"#9ca3af", marginTop:12, textAlign:"center" }}>
              {trend.reduce((s,d) => s+d.clicks, 0)} clicks in the last 7 days
            </p>
          </div>
        </div>

        {/* Link info */}
        <div style={S.card}>
          <h3 style={S.cardTitle}>🔗 Link Info</h3>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
            {[
              { label:"Short URL",    value: url.short_url },
              { label:"Status",       value: isDisabled ? "Disabled" : isExpired ? "Expired" : "Active" },
              { label:"Original URL", value: url.original_url, full:true },
              { label:"Short Code",   value: url.short_code },
            ].map((row,i) => (
              <div key={i} style={row.full ? { gridColumn:"1/-1" } : {}}>
                <div style={{ fontSize:11, color:"#9ca3af", fontWeight:600, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:4 }}>{row.label}</div>
                <div style={{ fontSize:13, color:"#111827", background:"#f9fafb", borderRadius:8, padding:"8px 12px", wordBreak:"break-all", fontFamily:"monospace" }}>{row.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent clicks */}
        {clicks.length > 0 && (
          <div style={{ ...S.card, marginTop:20 }}>
            <h3 style={S.cardTitle}>🖱️ Recent Clicks</h3>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:13 }}>
                <thead>
                  <tr style={{ borderBottom:"2px solid #f3f4f6" }}>
                    {["#","Time","IP Address"].map(h => <th key={h} style={{ textAlign:"left", padding:"8px 12px", color:"#9ca3af", fontWeight:600, fontSize:11, textTransform:"uppercase" }}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {clicks.map((c,i) => (
                    <tr key={c.id} style={{ borderBottom:"1px solid #f9fafb" }}>
                      <td style={{ padding:"10px 12px", color:"#9ca3af" }}>{i+1}</td>
                      <td style={{ padding:"10px 12px", color:"#374151" }}>{new Date(c.clicked_at).toLocaleString()}</td>
                      <td style={{ padding:"10px 12px", color:"#374151", fontFamily:"monospace" }}>{c.ip_address ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Edit Modal */}
      {showEdit && (
        <Modal title="✏️ Edit Expiration" onClose={() => setShowEdit(false)}>
          <p style={{ fontSize:14, color:"#6b7280", marginTop:0, marginBottom:20 }}>Set a new expiration for <strong>/{url.short_code}</strong>.</p>
          <label style={{ display:"flex", alignItems:"center", gap:10, cursor:"pointer" }}>
            <input type="checkbox" checked={noExpiry} onChange={e => setNoExpiry(e.target.checked)} style={{ width:16, height:16 }} />
            <span style={{ fontSize:14, color:"#374151" }}>No expiration (link lives forever)</span>
          </label>
          {!noExpiry && (
            <div style={{ marginTop:16 }}>
              <label style={{ display:"block", fontSize:12, fontWeight:600, color:"#374151", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.06em" }}>Expires in (days from now)</label>
              <input type="number" value={editDays} min={1} max={365} onChange={e => setEditDays(e.target.value)} style={{ width:"100%", padding:"10px 14px", border:"1.5px solid #e5e7eb", borderRadius:8, fontSize:14, color:"#111827", outline:"none" }} placeholder="e.g. 30" />
              {editDays && !isNaN(editDays) && (
                <p style={{ fontSize:12, color:"#6b7280", marginTop:6 }}>
                  Expires on: {new Date(Date.now() + parseInt(editDays)*86400000).toLocaleDateString("en-GB",{day:"numeric",month:"long",year:"numeric"})}
                </p>
              )}
            </div>
          )}
          <div style={{ display:"flex", gap:10, marginTop:24 }}>
            <button onClick={() => setShowEdit(false)} style={S.btnOutline}>Cancel</button>
            <button onClick={handleEdit} disabled={saving||(!noExpiry&&(!editDays||isNaN(editDays)))} style={{ ...S.btnPrimary, opacity:saving?0.7:1 }}>
              {saving ? "Saving…" : "Save Changes"}
            </button>
          </div>
        </Modal>
      )}

      {/* Delete Modal */}
      {showDelete && (
        <Modal title="🗑️ Delete URL" onClose={() => setShowDelete(false)}>
          <div style={{ background:"#fef2f2", border:"1px solid #fecaca", borderRadius:10, padding:"14px 16px", marginBottom:20 }}>
            <p style={{ margin:0, fontSize:14, color:"#991b1b", fontWeight:500 }}>⚠️ This action is <strong>permanent</strong>. The short URL, all click history and analytics will be erased and cannot be recovered.</p>
          </div>
          <div style={{ background:"#f9fafb", borderRadius:8, padding:"10px 14px", marginBottom:20 }}>
            <div style={{ fontSize:11, color:"#9ca3af", fontWeight:600, textTransform:"uppercase", marginBottom:4 }}>You are deleting</div>
            <div style={{ fontSize:13, color:"#111827", fontFamily:"monospace", wordBreak:"break-all" }}>{url.short_url}</div>
          </div>
          <div style={{ display:"flex", gap:10 }}>
            <button onClick={() => setShowDelete(false)} style={{ ...S.btnOutline, flex:1 }}>Cancel</button>
            <button onClick={handleDelete} disabled={deleting} style={{ flex:1, padding:"11px 0", borderRadius:8, border:"none", background:"#ef4444", color:"#fff", fontWeight:700, fontSize:14, cursor:"pointer", opacity:deleting?0.7:1 }}>
              {deleting ? "Deleting…" : "Yes, Delete Forever"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

const S = {
  centered:   { display:"flex", alignItems:"center", justifyContent:"center", minHeight:"60vh" },
  spinner:    { width:40, height:40, border:"4px solid #e5e7eb", borderTop:"4px solid #6366f1", borderRadius:"50%", animation:"spin 0.8s linear infinite" },
  errorBox:   { background:"#fff", borderRadius:16, padding:40, textAlign:"center", maxWidth:400, display:"flex", flexDirection:"column", alignItems:"center", gap:8 },
  backBtn:    { background:"none", border:"none", cursor:"pointer", fontSize:13, color:"#6366f1", fontWeight:600, padding:"0 0 20px", display:"block" },
  header:     { display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:16, flexWrap:"wrap", marginBottom:24 },
  title:      { margin:0, fontSize:28, fontWeight:800, color:"#111827", fontFamily:"Syne,sans-serif", letterSpacing:"-0.02em" },
  originalUrl:{ margin:0, fontSize:13, color:"#9ca3af", maxWidth:460, wordBreak:"break-all" },
  badge:      { padding:"3px 10px", borderRadius:99, fontSize:12, fontWeight:700, letterSpacing:"0.05em", textTransform:"uppercase" },
  statsRow:   { display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:20 },
  statCard:   { background:"#fff", borderRadius:14, padding:"16px 18px", boxShadow:"0 1px 4px rgba(0,0,0,0.06)", display:"flex", alignItems:"center", gap:12 },
  card:       { background:"#fff", borderRadius:14, padding:"20px 22px", boxShadow:"0 1px 4px rgba(0,0,0,0.06)" },
  cardTitle:  { margin:"0 0 14px", fontSize:15, fontWeight:700, color:"#111827", fontFamily:"Syne,sans-serif" },
  btnPrimary: { background:"#6366f1", color:"#fff", border:"none", borderRadius:8, padding:"11px 22px", fontWeight:700, fontSize:14, cursor:"pointer" },
  btnOutline: { background:"none", border:"1.5px solid #e5e7eb", borderRadius:8, padding:"9px 16px", fontWeight:600, fontSize:13, cursor:"pointer", color:"#374151", whiteSpace:"nowrap" },
};