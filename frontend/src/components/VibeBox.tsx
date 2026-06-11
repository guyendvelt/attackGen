import { Sparkles } from "lucide-react";

interface Props {
  value: string;
  active: boolean;
  onChange: (value: string) => void;
  onFocus: () => void;
}

export default function VibeBox({ value, active, onChange, onFocus }: Props) {
  return (
    <div
      className={`glass rounded-2xl p-4 transition-all ${
        active ? "ring-2 ring-fuchsia-500/70" : "hover:ring-1 hover:ring-white/20"
      }`}
    >
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-fuchsia-300">
        <Sparkles size={16} />
        Vibe Generate
        <span className="font-normal text-gray-500">— describe any scenario</span>
      </div>
      <textarea
        value={value}
        onFocus={onFocus}
        onChange={(e) => onChange(e.target.value)}
        rows={2}
        placeholder="e.g. supply-chain implant that hides in a build pipeline, then beacons out…"
        className="w-full resize-none rounded-xl bg-black/30 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-fuchsia-500/50"
      />
    </div>
  );
}
