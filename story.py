"""Produce the written attack story from a composed Dataset.

Primary path: Azure OpenAI (gpt-4o), driven by the ACTUAL skill definition in
`.claude/skills/attack-story-writer/SKILL.md` — its body is loaded at runtime and
used as the system prompt, so the skill file is the single source of truth. (A web
server can't invoke a Claude Code skill directly; this is how we use it live.)

Falls back to a deterministic template if Azure isn't configured or the call fails,
so the endpoint never errors on story generation.
"""
from __future__ import annotations
import os

# Load .env if present (no-op if python-dotenv isn't installed).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except Exception:
    pass

_PHASE_ORDER = ["discovery", "staging", "persistence", "privilege_escalation",
                "execution", "defense_evasion", "data_collection",
                "data_exfiltration", "cleanup", "impact"]

_SKILL_PATH = os.path.join(
    os.path.dirname(__file__), ".claude", "skills", "attack-story-writer", "SKILL.md"
)

# Adapts the skill's "write attack_story.md to disk" workflow to our return-text API.
_OUTPUT_ADAPTER = (
    "\n\n---\nIMPORTANT OUTPUT CONTRACT FOR THIS RUN:\n"
    "- You have NO filesystem and NO tools. Do NOT read or write any files.\n"
    "- Use ONLY the dataset context provided in the user message (it already contains the "
    "scenario, OS profile, benign categories, and the 20 malicious commands grouped by category).\n"
    "- Respond with ONLY the attack_story.md Markdown content itself — no preamble, no file paths.\n"
    "- Output RAW Markdown. Do NOT wrap the whole response in a ``` code fence."
)


def _strip_code_fence(text: str) -> str:
    """Remove an outer ```/```markdown fence if the model wrapped the whole story."""
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if len(lines) >= 2:
            lines = lines[1:]                      # drop opening ``` / ```markdown
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]                 # drop closing ```
            t = "\n".join(lines).strip()
    return t

# Used only if SKILL.md can't be read.
_FALLBACK_SYSTEM_PROMPT = (
    'You are the AttackGen "attack-story-writer". Write a demo-ready Markdown attack story for a '
    "SIMULATED process-command dataset. Text only; never suggest executing commands; invent no real "
    "targets/credentials/IPs. Sections: Title, Scenario, Executive Summary, Attack Timeline, "
    "Malicious Command Breakdown (group the 20 malicious commands by phase, quote process_name + "
    "command_line), Benign Lookalike Strategy, Why This Is Challenging for Blue Team, Safety Note. "
    "Professional, concise, one-to-two pages."
)


def _load_skill_prompt() -> str:
    """Return the SKILL.md body (YAML frontmatter stripped) + the output contract."""
    try:
        text = open(_SKILL_PATH, encoding="utf-8").read()
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) == 3:
                text = parts[2]
        return text.strip() + _OUTPUT_ADAPTER
    except Exception:
        return _FALLBACK_SYSTEM_PROMPT + _OUTPUT_ADAPTER


def _malicious_by_category(dataset) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for row in dataset.rows:
        if row.label == "malicious":
            out.setdefault(row.category, []).append(
                {"process_name": row.process_name, "command_line": row.command_line}
            )
    return out


def _benign_categories(dataset) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in dataset.rows:
        if row.label == "benign":
            counts[row.category] = counts.get(row.category, 0) + 1
    return counts


def _template_story(dataset) -> str:
    cats = _malicious_by_category(dataset)
    ordered = [c for c in _PHASE_ORDER if c in cats] + [c for c in cats if c not in _PHASE_ORDER]
    parts = [
        f"# AttackGen Attack Story — {dataset.request.scenario}\n",
        f"Scenario: **{dataset.request.scenario}** on a **{dataset.request.os_profile}** host. "
        f"20 malicious commands are blended into 200 benign operations.\n",
    ]
    for i, cat in enumerate(ordered, 1):
        ex = cats[cat][0]["command_line"]
        parts.append(f"{i}. **{cat.replace('_', ' ').title()}** — e.g. `{ex}`")
    parts.append(
        "\nThe operator progresses from initial reconnaissance through to objective, each step "
        "disguised within matching benign administrative noise."
    )
    return "\n".join(parts)


def _azure_story(dataset) -> str:
    from openai import AzureOpenAI

    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_MONITORING_KEY"),
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
    )
    user_payload = {
        "scenario": dataset.request.scenario,
        "os_profile": dataset.request.os_profile,
        "benign_categories": _benign_categories(dataset),
        "malicious_by_category": _malicious_by_category(dataset),
        "totals": {"benign": len(dataset.benign_rows), "malicious": len(dataset.malicious_rows)},
    }
    resp = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        max_tokens=1200,
        temperature=0.7,
        messages=[
            {"role": "system", "content": _load_skill_prompt()},
            {"role": "user", "content":
                "Write the attack_story.md for this SIMULATED dataset. Use only what the data "
                f"shows.\n\nDATASET CONTEXT (JSON):\n{user_payload}"},
        ],
    )
    return _strip_code_fence(resp.choices[0].message.content)


def _azure_configured() -> bool:
    return bool(
        (os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_MONITORING_KEY"))
        and os.getenv("AZURE_OPENAI_ENDPOINT")
    )


def generate_story(dataset) -> str:
    """Return the attack narrative. Azure OpenAI (skill-driven) when configured, else template."""
    if _azure_configured():
        try:
            return _azure_story(dataset)
        except Exception:
            pass  # never fail the endpoint on story generation
    return _template_story(dataset)
