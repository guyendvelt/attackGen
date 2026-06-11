"""Map UI scenario theme(s) + OS into composer category counts.

The UI stays simple (pick a theme + OS). All count logic lives here. Counts must
sum to exactly 200 (benign) and 20 (malicious); see attackgen.models.
"""
from __future__ import annotations

# Benign mix (Σ = 200) — only categories present in the sample Linux seed.
_DEFAULT_BENIGN = {
    "linux_admin": 40, "devops": 35, "logs": 35,
    "backup": 45, "app_runtime": 25, "package_management": 20,
}
# Malicious mix (Σ = 20) — kill-chain phases present in the sample seed.
_DEFAULT_MALICIOUS = {
    "discovery": 4, "staging": 4, "persistence": 3,
    "execution": 5, "cleanup": 2, "impact": 2,
}

# Per-scenario malicious mix over the DB's kill-chain phase categories
# (discovery, staging, persistence, execution, cleanup, impact). Each row Σ = 20 and
# every value ≤ 12 (the per-category inventory in the sample seed). Each scenario
# emphasises the phases that define it, so the 20 malicious commands + the story
# differ per attack type. Extend as the DB owner adds scenario-specific rows.
_SCENARIO_MALICIOUS = {
    "ransomware":           {"discovery": 3, "staging": 4, "persistence": 2, "execution": 4, "cleanup": 2, "impact": 5},
    "lateral_movement":     {"discovery": 5, "staging": 3, "persistence": 3, "execution": 6, "cleanup": 2, "impact": 1},
    "persistence":          {"discovery": 2, "staging": 2, "persistence": 8, "execution": 4, "cleanup": 2, "impact": 2},
    "credential_dumping":   {"discovery": 6, "staging": 6, "persistence": 2, "execution": 3, "cleanup": 2, "impact": 1},
    "reverse_shell":        {"discovery": 3, "staging": 2, "persistence": 3, "execution": 9, "cleanup": 2, "impact": 1},
    "data_exfiltration":    {"discovery": 4, "staging": 6, "persistence": 2, "execution": 4, "cleanup": 2, "impact": 2},
    "sql_exploitation":     {"discovery": 5, "staging": 3, "persistence": 2, "execution": 7, "cleanup": 2, "impact": 1},
    "crypto_miner":         {"discovery": 3, "staging": 3, "persistence": 4, "execution": 7, "cleanup": 2, "impact": 1},
    "privilege_escalation": {"discovery": 6, "staging": 2, "persistence": 3, "execution": 7, "cleanup": 1, "impact": 1},
    "defense_evasion":      {"discovery": 3, "staging": 2, "persistence": 3, "execution": 3, "cleanup": 8, "impact": 1},
}

KNOWN_SCENARIOS = set(_SCENARIO_MALICIOUS) | {"default"}


def build_categories(scenarios: list[str]) -> tuple[dict[str, int], dict[str, int], str]:
    """Return (benign_categories, malicious_categories, primary_scenario).

    For a single known scenario we use its tuned malicious mix; otherwise the
    default. `primary_scenario` steers the DB scenario_tag preference + story title.
    """
    primary = scenarios[0] if scenarios else "default"
    malicious = dict(_SCENARIO_MALICIOUS.get(primary, _DEFAULT_MALICIOUS))
    benign = dict(_DEFAULT_BENIGN)

    assert sum(benign.values()) == 200, f"benign must sum to 200, got {sum(benign.values())}"
    assert sum(malicious.values()) == 20, f"malicious must sum to 20, got {sum(malicious.values())}"
    return benign, malicious, primary
