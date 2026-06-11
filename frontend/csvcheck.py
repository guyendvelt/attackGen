"""Validate the CSV strings produced by src/csv.ts using Python's trusted parser.

Checks: correct headers, column counts, field round-trip integrity (escaping of
commas/quotes/newlines), scored CSV strips label+attack_type, ground-truth holds
exactly the malicious commands, and the malicious set matches across files.
"""
import csv
import io
import json
import sys

with open("/tmp/csv_check.json") as f:
    cases = json.load(f)

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
    return cond


def parse(text):
    return list(csv.reader(io.StringIO(text)))


for case in cases:
    name = case["name"]
    result = case["result"]
    rows = result["rows"]
    malicious = result["malicious"]

    # --- labeled CSV (4 cols) ---
    lab = parse(case["labeled"])
    check(lab[0] == ["process_name", "command_line", "label", "attack_type"],
          f"[{name}] labeled header wrong: {lab[0]}")
    check(len(lab) - 1 == len(rows), f"[{name}] labeled row count {len(lab)-1} != {len(rows)}")
    for i, (orig, got) in enumerate(zip(rows, lab[1:])):
        check(len(got) == 4, f"[{name}] labeled row {i} has {len(got)} cols")
        check(got == [orig["process_name"], orig["command_line"], orig["label"], orig["attack_type"]],
              f"[{name}] labeled row {i} mismatch:\n  orig={orig}\n  got ={got}")

    # --- scored CSV (2 cols, NO label/attack_type leaking) ---
    sc = parse(case["scored"])
    check(sc[0] == ["process_name", "command_line"], f"[{name}] scored header wrong: {sc[0]}")
    check(len(sc) - 1 == len(rows), f"[{name}] scored row count {len(sc)-1} != {len(rows)}")
    for i, (orig, got) in enumerate(zip(rows, sc[1:])):
        check(len(got) == 2, f"[{name}] scored row {i} has {len(got)} cols (label leaked?)")
        check(got == [orig["process_name"], orig["command_line"]],
              f"[{name}] scored row {i} mismatch")
    # no label/attack_type values anywhere in scored
    flat = [c for row in sc[1:] for c in row]
    check("malicious" not in flat and "benign" not in flat,
          f"[{name}] scored CSV leaks label values")

    # --- ground-truth CSV (3 cols) ---
    gt = parse(case["groundtruth"])
    check(gt[0] == ["process_name", "command_line", "attack_type"],
          f"[{name}] groundtruth header wrong: {gt[0]}")
    check(len(gt) - 1 == len(malicious), f"[{name}] groundtruth count {len(gt)-1} != {len(malicious)}")
    for i, (orig, got) in enumerate(zip(malicious, gt[1:])):
        check(got == [orig["process_name"], orig["command_line"], orig["attack_type"]],
              f"[{name}] groundtruth row {i} mismatch")

    # --- cross-check: every ground-truth command appears as a malicious row ---
    lab_mal = {(r[0], r[1]) for r in lab[1:] if r[2] == "malicious"}
    gt_set = {(r[0], r[1]) for r in gt[1:]}
    check(gt_set <= lab_mal, f"[{name}] ground-truth cmd not found among malicious rows")
    check(len(lab_mal) == sum(1 for r in rows if r["label"] == "malicious"),
          f"[{name}] malicious count mismatch in labeled CSV")

    print(f"[{name}] rows={len(rows)} malicious={len(malicious)} "
          f"-> labeled/scored/groundtruth parsed OK")

print()
if failures:
    print("FAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("ALL CHECKS PASSED ✓")
