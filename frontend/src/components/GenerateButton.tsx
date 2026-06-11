import { Loader2, Zap } from "lucide-react";

interface Props {
  loading: boolean;
  disabled: boolean;
  onClick: () => void;
}

export default function GenerateButton({ loading, disabled, onClick }: Props) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className="group relative w-full overflow-hidden rounded-2xl bg-gradient-to-r from-rose-500 via-fuchsia-500 to-indigo-500 bg-[length:200%_100%] px-6 py-4 text-base font-bold text-white shadow-lg transition-all hover:bg-[100%_0] disabled:cursor-not-allowed disabled:opacity-40 animate-gradient-shift"
    >
      <span className="flex items-center justify-center gap-2">
        {loading ? (
          <>
            <Loader2 size={18} className="animate-spin" />
            Generating attack…
          </>
        ) : (
          <>
            <Zap size={18} />
            Generate Attack
          </>
        )}
      </span>
    </button>
  );
}
