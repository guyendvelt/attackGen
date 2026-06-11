import { useState } from "react";
import { BookOpen, Download, Eye, EyeOff, FileText, ListChecks } from "lucide-react";
import type { GenerateResult } from "../types";
import { downloadText, toGroundTruthCsv, toLabeledCsv, toScoredCsv } from "../csv";

interface Props {
  result: GenerateResult;
  scenarioLabel: string;
}

function Stat({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="glass flex-1 rounded-xl px-4 py-3">
      <div className="text-2xl font-bold" style={{ color: accent }}>
        {value}
      </div>
      <div className="text-xs uppercase tracking-wide text-gray-400">{label}</div>
    </div>
  );
}

export default function ResultView({ result, scenarioLabel }: Props) {
  const [showLabels, setShowLabels] = useState(true);
  const total = result.rows.length;
  const malicious = result.rows.filter((r) => r.label === "malicious").length;
  const benign = total - malicious;

  // Per-technique breakdown of the malicious commands (chain stages).
  const breakdown = result.malicious.reduce<Record<string, number>>((acc, m) => {
    acc[m.attack_type] = (acc[m.attack_type] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-5">
      {/* Attack story */}
      <div className="glass rounded-2xl p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-rose-300">
          <BookOpen size={16} />
          Attack Story — {scenarioLabel}
        </div>
        <p className="text-sm leading-relaxed text-gray-300">{result.story}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {Object.entries(breakdown).map(([type, count]) => (
            <span
              key={type}
              className="rounded-full bg-rose-500/15 px-2.5 py-0.5 text-xs font-medium text-rose-200"
            >
              {type} · {count}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-3">
        <Stat label="Total rows" value={total} accent="#a5b4fc" />
        <Stat label="Malicious" value={malicious} accent="#f43f5e" />
        <Stat label="Benign" value={benign} accent="#34d399" />
      </div>

      {/* Downloads */}
      <div className="flex flex-wrap gap-3">
        <DownloadBtn
          icon={<FileText size={16} />}
          label="Download CSV (labeled)"
          onClick={() => downloadText("attack_labeled.csv", toLabeledCsv(result))}
        />
        <DownloadBtn
          icon={<Download size={16} />}
          label="Download scored CSV (no labels)"
          onClick={() => downloadText("attack_scored.csv", toScoredCsv(result))}
        />
        <DownloadBtn
          icon={<ListChecks size={16} />}
          label="Ground-truth (20 malicious)"
          onClick={() => downloadText("ground_truth.csv", toGroundTruthCsv(result))}
        />
      </div>

      {/* Table preview */}
      <div className="glass overflow-hidden rounded-2xl">
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
          <span className="text-sm font-semibold text-gray-200">Dataset preview</span>
          <button
            onClick={() => setShowLabels((v) => !v)}
            className="flex items-center gap-1.5 rounded-lg bg-white/5 px-2.5 py-1 text-xs text-gray-300 hover:bg-white/10"
          >
            {showLabels ? <EyeOff size={14} /> : <Eye size={14} />}
            {showLabels ? "Hide labels" : "Show labels"}
          </button>
        </div>
        <div className="scrollbar-thin max-h-[420px] overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-[#12121a] text-gray-400">
              <tr>
                <th className="px-4 py-2 font-medium">process_name</th>
                <th className="px-4 py-2 font-medium">command_line</th>
                {showLabels && <th className="px-4 py-2 font-medium">label</th>}
                {showLabels && <th className="px-4 py-2 font-medium">attack_type</th>}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((r, i) => {
                const mal = r.label === "malicious";
                return (
                  <tr
                    key={i}
                    className={`border-t border-white/5 ${
                      showLabels && mal ? "bg-rose-500/10" : "hover:bg-white/5"
                    }`}
                  >
                    <td className="whitespace-nowrap px-4 py-1.5 font-mono text-gray-300">
                      {r.process_name}
                    </td>
                    <td className="px-4 py-1.5 font-mono text-gray-400">{r.command_line}</td>
                    {showLabels && (
                      <td className="px-4 py-1.5">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                            mal ? "bg-rose-500/20 text-rose-300" : "bg-emerald-500/15 text-emerald-300"
                          }`}
                        >
                          {r.label}
                        </span>
                      </td>
                    )}
                    {showLabels && (
                      <td className="whitespace-nowrap px-4 py-1.5 font-mono text-[11px] text-gray-500">
                        {r.attack_type}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DownloadBtn({
  icon,
  label,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="glass flex items-center gap-2 rounded-xl px-3.5 py-2 text-sm font-medium text-gray-200 transition-all hover:-translate-y-0.5 hover:text-white"
    >
      {icon}
      {label}
    </button>
  );
}
