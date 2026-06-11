import type { GenerateResult } from "./types";

function escapeCsv(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/** Full CSV with label + attack_type (process_name, command_line, label, attack_type). */
export function toLabeledCsv(result: GenerateResult): string {
  const header = "process_name,command_line,label,attack_type";
  const lines = result.rows.map(
    (r) => `${escapeCsv(r.process_name)},${escapeCsv(r.command_line)},${r.label},${r.attack_type}`
  );
  return [header, ...lines].join("\n");
}

/** Scored CSV: label column stripped (what the Blue team receives). */
export function toScoredCsv(result: GenerateResult): string {
  const header = "process_name,command_line";
  const lines = result.rows.map(
    (r) => `${escapeCsv(r.process_name)},${escapeCsv(r.command_line)}`
  );
  return [header, ...lines].join("\n");
}

/** Ground-truth list of the 20 malicious commands shared with the judges. */
export function toGroundTruthCsv(result: GenerateResult): string {
  const header = "process_name,command_line,attack_type";
  const lines = result.malicious.map(
    (m) => `${escapeCsv(m.process_name)},${escapeCsv(m.command_line)},${m.attack_type}`
  );
  return [header, ...lines].join("\n");
}

export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
