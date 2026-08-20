import { useCallback, useEffect, useState } from "react";
import DiscoveryScreen from "./components/DiscoveryScreen";
import AgentDetailScreen from "./components/AgentDetailScreen";
import { fetchIdentities, fetchDashboardSummary } from "./api/client";

export default function App() {
  const [tab, setTab] = useState("discovery");
  const [identities, setIdentities] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [idList, sum] = await Promise.all([fetchIdentities(), fetchDashboardSummary()]);
      setIdentities(idList);
      setSummary(sum);
      if (!selectedAccountId && idList.length > 0) {
        setSelectedAccountId(idList[0].account_id);
      }
    } catch {
      // Backend not reachable yet / no data ingested — leave empty state.
    } finally {
      setLoading(false);
    }
  }, [selectedAccountId]);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="app-shell">
      <div className="topbar">
        <div className="brand">
          <div className="brand-mark">NHI</div>
          <div className="brand-text">
            <h1>Non-Human Identity Governance</h1>
            <span>machine credential discovery &amp; risk evaluation</span>
          </div>
        </div>
        <div className="nav-tabs">
          <button className={`nav-tab ${tab === "discovery" ? "active" : ""}`} onClick={() => setTab("discovery")}>
            1 · Discovery &amp; Register
          </button>
          <button className={`nav-tab ${tab === "detail" ? "active" : ""}`} onClick={() => setTab("detail")}>
            2 · Agent Risk Analysis
          </button>
        </div>
      </div>

      <div className="main-content">
        {tab === "discovery" ? (
          <DiscoveryScreen
            identities={identities}
            summary={summary}
            loading={loading}
            onDataChanged={refresh}
            onSelectAgent={setSelectedAccountId}
            onGoToDetail={() => setTab("detail")}
          />
        ) : (
          <AgentDetailScreen
            identities={identities}
            selectedAccountId={selectedAccountId}
            onSelect={setSelectedAccountId}
          />
        )}
      </div>
    </div>
  );
}
