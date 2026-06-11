export interface Scenario {
  id: string;
  name: string;
  icon: string;
  description: string;
  color: string;
}

export type Label = "malicious" | "benign";
export type TargetOS = "windows" | "linux";

export interface Row {
  process_name: string;
  command_line: string;
  label: Label;
  attack_type: string;
}

export interface MaliciousCmd {
  process_name: string;
  command_line: string;
  attack_type: string;
}

export interface GenerateResult {
  story: string;
  rows: Row[];
  malicious: MaliciousCmd[];
}

export interface GenerateRequest {
  scenario_ids: string[];
  os: TargetOS;
  seed?: number;
}
