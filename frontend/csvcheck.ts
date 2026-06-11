// Exercises the REAL production CSV builders from src/csv.ts and dumps their
// output to /tmp/csv_check.json for cross-validation with Python's csv parser.
import { toGroundTruthCsv, toLabeledCsv, toScoredCsv } from "./src/csv";
import type { GenerateResult } from "./src/types";

// Adversarial fixture: commas, double-quotes, and a real newline in a field.
const adversarial: GenerateResult = {
  story: "adversarial",
  rows: [
    { process_name: "cmd.exe", command_line: 'echo "a,b" && dir', label: "malicious", attack_type: "test" },
    { process_name: "bash", command_line: "printf 'l1\nl2'", label: "benign", attack_type: "benign" },
    { process_name: "powershell.exe", command_line: 'gci -Include *.docx,*.xlsx', label: "malicious", attack_type: "ransomware" },
    { process_name: "git", command_line: "git commit -m \"fix, again\"", label: "benign", attack_type: "benign" },
  ],
  malicious: [
    { process_name: "cmd.exe", command_line: 'echo "a,b" && dir', attack_type: "test" },
    { process_name: "powershell.exe", command_line: 'gci -Include *.docx,*.xlsx', attack_type: "ransomware" },
  ],
};

async function fetchReal(): Promise<GenerateResult> {
  const url =
    "http://127.0.0.1:8000/api/generate?scenario_ids=ransomware&scenario_ids=data_exfiltration&os=windows";
  const res = await fetch(url);
  if (!res.ok) throw new Error(`backend ${res.status}`);
  return res.json();
}

function pack(name: string, r: GenerateResult) {
  return {
    name,
    result: r,
    labeled: toLabeledCsv(r),
    scored: toScoredCsv(r),
    groundtruth: toGroundTruthCsv(r),
  };
}

const real = await fetchReal();
const out = [pack("adversarial", adversarial), pack("real", real)];

const fs = await import("node:fs");
fs.writeFileSync("/tmp/csv_check.json", JSON.stringify(out, null, 2));
console.log("wrote /tmp/csv_check.json | cases:", out.map((o) => o.name).join(", "));
