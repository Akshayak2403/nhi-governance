import { useEffect, useState } from "react";
import StatusBadge from "./StatusBadge";
import { fetchAgentRisk } from "../api/client";

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export default function AgentDetailScreen({ identities, selectedAccountId, onSelect }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!selectedAccountId) return;
    setLoading(true);
    setError(null);
    fetchAgentRisk(selectedAccountId)
      .then(setDetail)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedAccountId]);

  if (identities.length === 0) {
    return (
      <div className="panel">
        <div className="empty-state">
          <div className="es-icon">🛰️</div>
          <p><strong>No identities to analyze yet.</strong></p>
          <p>Run a discovery scan on the Discovery &amp; Asset Register screen first.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="detail-layout">
      <div className="agent-sidebar panel">
        <p className="panel-title">Identities</p>
        <p className="panel-subtitle">Select one to inspect its risk profile.</p>
        {identities.map((idn) => (
          <div
            key={idn.account_id}
            className={`agent-list-item ${idn.account_id === selectedAccountId ? "active" : ""}`}
            onClick={() => onSelect(idn.account_id)}
          >
            <span className="acct-id">
              {idn.account_id} {idn.is_orphan && "🔴"}
            </span>
            <StatusBadge status={idn.overall_status} />
          </div>
        ))}
      </div>

      <div className="panel">
        {loading && (
          <div className="center-flex">
            <span className="loading-spin" /> Evaluating identity…
          </div>
        )}
        {error && <div className="status-line err">{error}</div>}

        {detail && !loading && (
          <>
            <div className="detail-header">
              <div>
                <h2>{detail.account_id}</h2>
                <div className="detail-meta">
                  {detail.owner_agent ? (
                    <>Owned by <strong style={{ color: "var(--text)" }}>{detail.owner_agent}</strong></>
                  ) : (
                    <span style={{ color: "var(--critical)" }}>⚠ No registered owner — orphan identity</span>
                  )}
                  {detail.registered_purpose && <> · Purpose: {detail.registered_purpose}</>}
                </div>
              </div>
              <StatusBadge status={detail.overall_status} />
            </div>

            <div className="section">
              <div className="section-title">⚠ Risk Findings</div>
              {detail.findings.length === 0 ? (
                <div className="finding-card" style={{ borderColor: "var(--compliant-border)", background: "var(--compliant-bg)" }}>
                  <div className="finding-title" style={{ color: "var(--compliant)" }}>
                    No policy violations detected
                  </div>
                  <div className="finding-msg">
                    This identity's granted permissions are all actively used and it holds no conflicting capabilities.
                  </div>
                </div>
              ) : (
                detail.findings.map((f, i) => (
                  <div className={`finding-card ${f.severity}`} key={i}>
                    <div className="finding-head">
                      <span className={`badge badge-${f.severity === "critical" ? "critical" : "warning"}`}>
                        {f.check_type.replace("_", " ")}
                      </span>
                      <span className="finding-title">{f.title}</span>
                    </div>
                    <div className="finding-msg">{f.message}</div>
                    <div className="finding-action">→ {f.recommended_action}</div>
                  </div>
                ))
              )}
            </div>

            <div className="section">
              <div className="section-title">🔑 Permissions Granted vs. Used (Last 30 Days)</div>
              {detail.permission_comparison.map((p) => (
                <div
                  key={p.permission}
                  className={`perm-row ${!p.granted ? "flag-shadow" : !p.used_in_window ? "flag-unused" : ""}`}
                >
                  <div className="perm-left">
                    <span className="perm-name">{p.permission}</span>
                    {p.sensitive && <span className="perm-sensitive">SENSITIVE</span>}
                  </div>
                  <div className="perm-right">
                    {p.used_in_window ? (
                      <div className="perm-used">✓ used {formatTime(p.last_used)}</div>
                    ) : (
                      <div className="perm-unused">— unused in window</div>
                    )}
                    {p.recommendation && <div className="perm-rec">{p.recommendation}</div>}
                  </div>
                </div>
              ))}
            </div>

            <div className="section">
              <div className="section-title">🕒 Activity Timeline</div>
              {detail.timeline.length === 0 ? (
                <p className="panel-subtitle">No activity recorded in the last 30 days.</p>
              ) : (
                <div className="timeline">
                  {detail.timeline.map((e, i) => (
                    <div className={`tl-item ${e.flagged ? "flagged" : ""}`} key={i}>
                      <div className="tl-time">{formatTime(e.timestamp)}</div>
                      <div className="tl-action">
                        <b>{e.action}</b> → {e.resource}
                      </div>
                      {e.flagged && <div className="tl-flag">🚩 {e.flag_reason}</div>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
