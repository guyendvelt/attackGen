"""Mock dataset generator (Phase 1).

Produces a dataset of ~220 process commands: exactly 20 malicious (telling a
coherent attack story) + ~200 benign noise, shuffled, with an attack narrative.

Supports chaining MULTIPLE attack techniques into one dataset: the 20 malicious
commands are split across the selected scenarios in selection order, so the result
reads as a single multi-stage attack.

Every row carries a 4th `attack_type` column (the technique id for malicious rows,
"benign" for noise) so the dataset is queryable by technique. `attack_type` and
`label` are both stripped from the Blue team's scored CSV.

The public function `generate_dataset` has the exact shape the LLM phase will
keep: swap the internals, leave the return contract untouched.
"""

import random
from typing import Dict, List, Optional

import scenarios as S

BENIGN_TARGET = 200
MALICIOUS_TARGET = 20


def _fill(template: str, rnd: random.Random) -> str:
    """Substitute {tokens} in a benign template with realistic values."""
    return (
        template.replace("{repo}", rnd.choice(S.REPOS))
        .replace("{svc}", rnd.choice(S.SVCS))
        .replace("{user}", rnd.choice(S.USERS))
        .replace("{host}", rnd.choice(S.HOSTS))
    )


def _vary_malicious(cmd: Dict[str, str], rnd: random.Random) -> Dict[str, str]:
    """Lightly vary a malicious beat so repeats aren't byte-identical."""
    cl = cmd["command_line"]
    if "WS-042" in cl:
        cl = cl.replace("WS-042", rnd.choice(S.HOSTS))
    if "10.0.0.42" in cl:
        cl = cl.replace("10.0.0.42", rnd.choice(S.IPS))
    return {"process_name": cmd["process_name"], "command_line": cl}


def _expand_beats(
    beats: List[Dict[str, str]], target: int, attack_type: str, rnd: random.Random
) -> List[Dict[str, str]]:
    """Take a scenario's ordered beats and produce exactly `target` rows."""
    out: List[Dict[str, str]] = [dict(b) for b in beats[:target]]
    i = 0
    while len(out) < target:
        out.append(_vary_malicious(beats[i % len(beats)], rnd))
        i += 1
    out = out[:target]
    for c in out:
        c["label"] = "malicious"
        c["attack_type"] = attack_type
    return out


def _split_counts(total: int, n: int) -> List[int]:
    """Split `total` as evenly as possible into `n` buckets (front-loaded)."""
    base, rem = divmod(total, n)
    return [base + (1 if i < rem else 0) for i in range(n)]


def _resolve_scenarios(scenario_ids: Optional[List[str]]) -> List[str]:
    valid = [s for s in (scenario_ids or []) if s in S.BEATS]
    return valid or ["lateral_movement"]


def _build_malicious(
    scenario_ids: List[str], os_name: str, rnd: random.Random
) -> List[Dict[str, str]]:
    """Split exactly 20 malicious commands across the selected scenarios."""
    counts = _split_counts(MALICIOUS_TARGET, len(scenario_ids))
    out: List[Dict[str, str]] = []
    for sid, count in zip(scenario_ids, counts):
        beats = S.BEATS[sid][os_name]
        out.extend(_expand_beats(beats, count, sid, rnd))
    return out  # exactly MALICIOUS_TARGET rows


def _build_benign(os_name: str, rnd: random.Random) -> List[Dict[str, str]]:
    pool = S.BENIGN[os_name]
    out: List[Dict[str, str]] = []
    while len(out) < BENIGN_TARGET:
        base = rnd.choice(pool)
        out.append({
            "process_name": base["process_name"],
            "command_line": _fill(base["command_line"], rnd),
            "label": "benign",
            "attack_type": "benign",
        })
    return out


def _story(scenario_ids: List[str], vibe: Optional[str], os_name: str, had_presets: bool) -> str:
    if not had_presets:
        label = vibe.strip() if vibe else "custom scenario"
        return (
            f"Custom scenario: \"{label}\". The generated attack lands an initial foothold, "
            f"escalates and establishes persistence, then acts on objectives across the host "
            f"({os_name}). (Scenario-specific command synthesis arrives with the LLM phase.)"
        )

    names = [S.NAME.get(s, s) for s in scenario_ids]
    if len(names) == 1:
        chain = names[0]
    else:
        chain = " → ".join(names)
        chain = f"a multi-stage chain ({chain})"
    intro = f"This attack is {chain}. " if len(names) > 1 else ""
    parts = [S.STORY[s] for s in scenario_ids if s in S.STORY]
    return intro + " ".join(parts)


def generate_dataset(
    scenario_ids: Optional[List[str]] = None,
    vibe: Optional[str] = None,
    os_name: str = "windows",
    seed: Optional[int] = None,
) -> Dict:
    """Return {story, rows[], malicious[]} for the requested scenario(s).

    Exactly 20 malicious rows (split across the selected scenarios) + ~200 benign,
    shuffled together. Each row has process_name, command_line, label, attack_type.
    `malicious` is the separate ground-truth list (no label column).
    """
    os_name = "linux" if str(os_name).lower().startswith("l") else "windows"
    rnd = random.Random(seed)

    had_presets = bool([s for s in (scenario_ids or []) if s in S.BEATS])
    resolved = _resolve_scenarios(scenario_ids)

    malicious = _build_malicious(resolved, os_name, rnd)
    benign = _build_benign(os_name, rnd)

    rows = malicious + benign
    rnd.shuffle(rows)

    return {
        "story": _story(resolved, vibe, os_name, had_presets),
        "rows": rows,
        "malicious": [
            {
                "process_name": c["process_name"],
                "command_line": c["command_line"],
                "attack_type": c["attack_type"],
            }
            for c in malicious
        ],
    }
