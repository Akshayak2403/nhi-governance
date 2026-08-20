const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function handle(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* response wasn't JSON */
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function uploadDirectory(file) {
  const form = new FormData();
  form.append("file", file);
  return handle(await fetch(`${BASE_URL}/api/ingest/directory`, { method: "POST", body: form }));
}

export async function uploadActivity(file) {
  const form = new FormData();
  form.append("file", file);
  return handle(await fetch(`${BASE_URL}/api/ingest/activity`, { method: "POST", body: form }));
}

export async function runScan() {
  return handle(await fetch(`${BASE_URL}/api/scan/run`, { method: "POST" }));
}

export async function fetchIdentities() {
  return handle(await fetch(`${BASE_URL}/api/identities`));
}

export async function fetchDashboardSummary() {
  return handle(await fetch(`${BASE_URL}/api/dashboard/summary`));
}

export async function fetchAgentRisk(accountId) {
  return handle(await fetch(`${BASE_URL}/api/agents/${encodeURIComponent(accountId)}/risk`));
}

export async function resetAll() {
  return handle(await fetch(`${BASE_URL}/api/reset`, { method: "DELETE" }));
}
