import { useState } from "react";
import FileDropzone from "./FileDropzone";
import StatusBadge from "./StatusBadge";
import { uploadDirectory, uploadActivity, runScan } from "../api/client";

export default function DiscoveryScreen({
  identities,
  summary,
  loading,
  onDataChanged,
  onSelectAgent,
  onGoToDetail,
}) {
  const [dirFile, setDirFile] = useState(null);
  const [actFile, setActFile] = useState(null);
  const [status, setStatus] = useState(null); // { type: 'ok'|'err'|'busy', text }
  const [busy, setBusy] = useState(false);

  async function handleRunDiscovery() {
    if (!dirFile || !actFile) {
      setStatus({ type: "err", text: "Select both the directory scan and the activity log JSON files first." });
      return;
    }
    setBusy(true);
    try {
      setStatus({ type: "busy", text: "Ingesting directory discovery data…" });
      const dirRes = await uploadDirectory(dirFile);
      setStatus({ type: "busy", text: "Ingesting 30-day activity logs…" });
      const actRes = await uploadActivity(actFile);
      setStatus({ type: "busy", text: "Running evaluation pipeline (orphan / least-privilege / SoD / purpose checks)…" });
      const scanRes = await runScan();
      setStatus({
        type: "ok",
        text: `Scan complete — ${scanRes.identities_discovered} identities evaluated, ${scanRes.orphans_found} orphan(s), ${scanRes.critical_findings} critical finding(s), ${dirRes.count} accounts / ${actRes.count} events ingested.`,
      });
      await onDataChanged();
    } catch (e) {
      setStatus({ type: "err", text: `Ingestion failed: ${e.message}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <p className="panel-title">Discovery &amp; Ingestion</p>
        <p className="panel-subtitle">
          Simulates a cloud directory scan + a 30-day activity log pull. Upload both mock JSON payloads, then run the
          discovery scan to map credentials to agents and evaluate risk.
        </p>
        <div className="upload-grid">
          <FileDropzone
            label="Directory Discovery JSON"
            hint="Discovered API keys &amp; service accounts, permissions, owners"
            icon="🗂️"
            file={dirFile}
            onFile={setDirFile}
          />
          <FileDropzone
            label="30-Day Activity Log JSON"
            hint="Per-account events: logins, API calls, DB queries"
            icon="📜"
            file={actFile}
            onFile={setActFile}
          />
        </div>
        <div className="action-row">
          <button className="btn btn-primary" disabled={busy} onClick={handleRunDiscovery}>
            {busy ? <span className="loading-spin" style={{ width: 14, height: 14 }} /> : "▶"} Run Discovery Scan
          </button>
          {status && (
            <span className={`status-line ${status.type === "err" ? "err" : status.type === "ok" ? "ok" : ""}`}>
              {status.text}
            </span>
          )}
        </div>
      </div>

      {summary && summary.total_identities > 0 && (
        <div className="summary-strip">
          <div className="stat-card accent">
            <div className="stat-value">{summary.total_identities}</div>
            <div className="stat-label">Identities Found</div>
          </div>
          <div className="stat-card crit">
            <div className="stat-value">{summary.orphan_identities}</div>
            <div className="stat-label">Orphan Identities</div>
          </div>
          <div className="stat-card crit">
            <div className="stat-value">{summary.sod_violations}</div>
            <div className="stat-label">SoD Violations</div>
          </div>
          <div className="stat-card warn">
            <div className="stat-value">{summary.over_provisioned}</div>
            <div className="stat-label">Over-Provisioned</div>
          </div>
          <div className="stat-card crit">
            <div className="stat-value">{summary.critical_findings}</div>
            <div className="stat-label">Critical Findings</div>
          </div>
        </div>
      )}

      <div className="panel">
        <p className="panel-title">Identity Register</p>
        <p className="panel-subtitle">Every discovered credential, mapped to its AI agent (or flagged as orphaned).</p>

        {loading ? (
          <div className="center-flex">
            <span className="loading-spin" /> Loading identities…
          </div>
        ) : identities.length === 0 ? (
          <div className="empty-state">
            <div className="es-icon">🔍</div>
            <p><strong>No identities discovered yet.</strong></p>
            <p>Upload the directory discovery and activity log JSON files above, then run the discovery scan.</p>
          </div>
        ) : (
          <div className="identity-table-wrap">
            <table className="identity-table">
              <thead>
                <tr>
                  <th>Account ID</th>
                  <th>Credential Type</th>
                  <th>Assigned AI Agent</th>
                  <th>Granted Permissions</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((idn) => (
                  <tr
                    key={idn.account_id}
                    className={idn.is_orphan ? "orphan-row" : ""}
                    onClick={() => {
                      onSelectAgent(idn.account_id);
                      onGoToDetail();
                    }}
                  >
                    <td>
                      <span className="acct-id">{idn.account_id}</span>
                      {idn.is_orphan && (
                        <span className="badge badge-critical" style={{ marginLeft: 8 }}>
                          <span className="badge-dot" /> Orphan
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="type-pill">{idn.credential_type}</span>
                    </td>
                    <td>
                      <span className={`owner-cell ${!idn.owner_agent ? "unassigned" : ""}`}>
                        {idn.owner_agent || "Unassigned — no registered owner"}
                      </span>
                    </td>
                    <td style={{ maxWidth: 260 }}>
                      <span className="mono" style={{ fontSize: 11.5, color: "var(--text-faint)" }}>
                        {idn.granted_permissions.slice(0, 3).join(", ")}
                        {idn.granted_permissions.length > 3 ? ` +${idn.granted_permissions.length - 3} more` : ""}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={idn.overall_status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
