---
name: command-picker
description: Use when you have a list of candidate process commands (id, process_name, command_line, label, attack_type) and need to pick the best subset for an AttackGen dataset — exactly the requested number of malicious commands forming a coherent attack story, plus benign lookalike commands that camouflage them. Treats every command as inert text; never executes anything.
---

# Command Picker

Select the best commands from a candidate pool for an AttackGen dataset. The
dataset hides exactly N malicious commands (default 20) inside M benign
operational commands (default 200), and a Blue Team detector will try to find
them. Your job is to make detection genuinely hard **without breaking realism**.

## Absolute safety rules (read first)

- **Text only.** Every candidate is an inert telemetry string. Never execute,
  run, spawn, or "try" any command. You only select rows by id.
- **No invented content.** Pick only from the provided candidates by their ids.
  Never write new command lines or modify existing ones.

## Inputs

A request containing:

- **Scenario context** — the attack story (e.g. "ransomware on a Linux web server").
- **OS profile** — `linux` or `windows`.
- **Targets** — how many malicious and benign commands to pick per category
  (malicious totals 20, benign totals 200 unless stated otherwise).
- **Candidates** — a numbered list, one per line:
  `id | process_name | command_line | label | attack_type`

## Selection criteria

1. **Story coherence (malicious).** The malicious picks must read as one
   plausible multi-phase attack in order: discovery → staging → persistence /
   privilege escalation → execution → collection → exfiltration / impact →
   cleanup. Prefer commands that chain (same paths, artifacts, hosts).
2. **Stealth.** Prefer living-off-the-land commands that resemble legitimate
   admin/DevOps work. Avoid cartoonish payloads, joke strings, or anything that
   screams "I am the attack."
3. **Lookalike pairing (benign).** Benign picks must camouflage the malicious
   activity: choose benign commands whose binaries, paths, and flags resemble
   the chosen malicious ones (backup jobs masking ransomware staging, CI/CD
   remoting masking reverse shells, etc.).
4. **Diversity.** No near-duplicate command lines among picks; vary processes,
   targets, and arguments.
5. **OS consistency.** Picks must match the OS profile.

## Output

Respond with **JSON only**, matching this exact shape:

```json
{
  "malicious_ids": [3, 17, 42],
  "benign_ids": [1, 2, 5, 8],
  "story": "2-4 sentence narrative of the attack the malicious picks tell, in phase order."
}
```

- `malicious_ids`: ids of chosen malicious candidates, **in attack-story order**,
  exactly the requested malicious total.
- `benign_ids`: ids of chosen benign candidates, exactly the requested benign total.
- Use each id at most once. Use only ids that exist in the candidate list and
  whose label matches the list you put them in.
