import { useEffect, useState } from "react";

type Health = { ok: boolean; node: string; sqlite: string };

// Foundation placeholder: confirms the web app can reach the API. Dashboard comes in M7.
export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setHealth)
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 p-8 font-sans">
      <h1 className="text-2xl font-semibold">AgentShield</h1>
      <p className="text-zinc-400 mt-1">Foundation build — API connectivity check</p>
      <pre className="mt-6 text-sm">
        {error ? `API unreachable: ${error}` : health ? JSON.stringify(health, null, 2) : "Checking…"}
      </pre>
    </main>
  );
}
