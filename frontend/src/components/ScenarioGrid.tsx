import { Check } from "lucide-react";
import type { Scenario } from "../types";

interface Props {
  scenarios: Scenario[];
  selectedIds: string[];
  onToggle: (id: string) => void;
}

export default function ScenarioGrid({ scenarios, selectedIds, onToggle }: Props) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
      {scenarios.map((s) => {
        const idx = selectedIds.indexOf(s.id);
        const active = idx !== -1;
        return (
          <button
            key={s.id}
            onClick={() => onToggle(s.id)}
            className={`glass group relative overflow-hidden rounded-2xl p-4 text-left transition-all duration-200 hover:-translate-y-0.5 ${
              active ? "ring-2" : "hover:ring-1 hover:ring-white/20"
            }`}
            style={active ? ({ ["--tw-ring-color" as string]: s.color } as React.CSSProperties) : undefined}
          >
            <div
              className="absolute -right-8 -top-8 h-24 w-24 rounded-full opacity-20 blur-2xl transition-opacity group-hover:opacity-40"
              style={{ background: s.color }}
            />
            {active && (
              <div
                className="absolute right-2 top-2 flex h-5 w-5 items-center justify-center rounded-full text-[11px] font-bold text-white"
                style={{ background: s.color }}
                title={`Stage ${idx + 1}`}
              >
                {idx + 1}
              </div>
            )}
            <div className="mb-2 text-2xl">{s.icon}</div>
            <div className="flex items-center gap-1.5 text-sm font-semibold text-white">
              {active && <Check size={13} style={{ color: s.color }} />}
              {s.name}
            </div>
            <div className="mt-1 text-xs leading-snug text-gray-400">{s.description}</div>
            {active && (
              <div className="absolute bottom-0 left-0 h-0.5 w-full" style={{ background: s.color }} />
            )}
          </button>
        );
      })}
    </div>
  );
}
