import type { GenerateRequest, GenerateResult, Scenario } from "./types";

export async function fetchScenarios(): Promise<Scenario[]> {
  const res = await fetch("/api/scenarios");
  if (!res.ok) throw new Error(`scenarios failed: ${res.status}`);
  return res.json();
}

export async function generate(req: GenerateRequest): Promise<GenerateResult> {
  const params = new URLSearchParams();
  req.scenario_ids.forEach((id) => params.append("scenario_ids", id));
  params.set("os", req.os);
  if (req.seed !== undefined) params.set("seed", String(req.seed));

  const res = await fetch(`/api/generate?${params.toString()}`);
  if (!res.ok) throw new Error(`generate failed: ${res.status}`);
  return res.json();
}
