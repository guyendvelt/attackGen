import { useEffect, useState } from "react";
import { Monitor, Sparkles, Terminal } from "lucide-react";
import { fetchScenarios, generate } from "./api";
import type { GenerateResult, Scenario, TargetOS } from "./types";
import ScenarioGrid from "./components/ScenarioGrid";
import GenerateButton from "./components/GenerateButton";
import ResultView from "./components/ResultView";

export default function App() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [os, setOs] = useState<TargetOS>("linux");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<GenerateResult | null>(null);

  useEffect(() => {
    fetchScenarios()
      .then(setScenarios)
      .catch((e) => setError(String(e)));
  }, []);

  const toggleScenario = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const canGenerate = selectedIds.length > 0;

  const scenarioLabel =
    selectedIds
      .map((id) => scenarios.find((s) => s.id === id)?.name ?? id)
      .join(" → ") || "Attack";

  const onGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await generate({ scenarios: selectedIds, os_profile: os });
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-aurora animate-gradient-shift min-h-screen">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        {/* Header */}
        <header className="mb-8">
          <div className="mb-1 flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-rose-500 via-fuchsia-500 to-indigo-500 font-black text-white">
              U
            </div>
            <div>
              <h1 className="text-xl font-bold text-white sm:text-2xl">
                Red Team — Attack Generator
              </h1>
              <p className="text-xs text-gray-400">You craft the attack. They hunt for it.</p>
            </div>
          </div>
        </header>

        {/* Controls */}
        <section className="glass rounded-3xl p-5 sm:p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-400">
              1 · Choose attack methods{" "}
              <span className="font-normal normal-case text-gray-600">
                (select one or more to chain)
              </span>
            </h2>
            <OsToggle os={os} setOs={setOs} />
          </div>

          <ScenarioGrid scenarios={scenarios} selectedIds={selectedIds} onToggle={toggleScenario} />

          {/* AI generation — parked for later */}
          <div className="mt-3 flex items-center gap-2 rounded-xl border border-dashed border-white/10 px-3 py-2 text-xs text-gray-600">
            <Sparkles size={14} />
            Generate with AI — coming soon
          </div>

          <div className="mt-5">
            <GenerateButton loading={loading} disabled={!canGenerate} onClick={onGenerate} />
          </div>

          {error && (
            <p className="mt-3 rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
              {error}
            </p>
          )}
        </section>

        {/* Results */}
        {result && (
          <section className="mt-8">
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-gray-400">
              2 · Generated dataset
            </h2>
            <ResultView result={result} scenarioLabel={scenarioLabel} />
          </section>
        )}

        <footer className="mt-10 text-center text-xs text-gray-600">
          Process-level commands only · ~220 rows · exactly 20 malicious · mock data
        </footer>
      </div>
    </div>
  );
}

function OsToggle({ os, setOs }: { os: TargetOS; setOs: (os: TargetOS) => void }) {
  return (
    <div className="glass flex items-center gap-1 rounded-full p-1 text-xs">
      <button
        onClick={() => setOs("windows")}
        className={`flex items-center gap-1.5 rounded-full px-3 py-1 transition-colors ${
          os === "windows" ? "bg-white/15 text-white" : "text-gray-400 hover:text-white"
        }`}
      >
        <Monitor size={14} /> Windows
      </button>
      <button
        onClick={() => setOs("linux")}
        className={`flex items-center gap-1.5 rounded-full px-3 py-1 transition-colors ${
          os === "linux" ? "bg-white/15 text-white" : "text-gray-400 hover:text-white"
        }`}
      >
        <Terminal size={14} /> Linux
      </button>
    </div>
  );
}
