"""Tests for backend/picker.py — no network calls anywhere."""
import random
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

import picker  # noqa: E402


@pytest.fixture()
def pool():
    rows = []
    for cat in ("ransomware", "persistence"):
        for i in range(30):
            rows.append({
                "process_name": "bash",
                "command_line": f"{cat}-mal-{i}",
                "label": "malicious",
                "attack_type": cat,
            })
        for i in range(60):
            rows.append({
                "process_name": "bash",
                "command_line": f"{cat}-ben-{i}",
                "label": "benign",
                "attack_type": cat,
            })
    return rows


def test_sample_candidates_counts_and_ids(pool):
    rnd = random.Random(7)
    cands = picker.sample_candidates(
        pool, ["ransomware", "persistence"], mal_per_cat=10, ben_per_cat=20, rnd=rnd
    )
    mal = [c for c in cands if c["label"] == "malicious"]
    ben = [c for c in cands if c["label"] == "benign"]
    assert len(mal) == 20 and len(ben) == 40
    # ids are unique and sequential from 1
    assert [c["id"] for c in cands] == list(range(1, len(cands) + 1))


def test_sample_candidates_caps_at_available(pool):
    rnd = random.Random(7)
    cands = picker.sample_candidates(
        pool, ["ransomware"], mal_per_cat=999, ben_per_cat=999, rnd=rnd
    )
    mal = [c for c in cands if c["label"] == "malicious"]
    assert len(mal) == 30  # only 30 available


def test_load_pool_csv_skips_malformed(tmp_path):
    p = tmp_path / "pool.csv"
    p.write_text(
        "process_name,command_line,label,attack_type\n"
        "bash,echo hi,benign,ransomware\n"
        "bash,broken row,who-knows,stderr\n"
        "pwsh,Get-Date,malicious,persistence\n"
    )
    rows = picker.load_pool_csv(p)
    assert len(rows) == 2
    assert {r["label"] for r in rows} == {"benign", "malicious"}


def _cands(n_mal, n_ben):
    cands = []
    i = 1
    for _ in range(n_mal):
        cands.append({"id": i, "process_name": "bash", "command_line": f"m{i}",
                      "label": "malicious", "attack_type": "ransomware"})
        i += 1
    for _ in range(n_ben):
        cands.append({"id": i, "process_name": "bash", "command_line": f"b{i}",
                      "label": "benign", "attack_type": "ransomware"})
        i += 1
    return cands


def test_finalize_happy_path():
    cands = _cands(5, 8)
    mal, ben = picker.finalize_selection([1, 2, 3], [6, 7, 8, 9], cands,
                                         mal_target=3, ben_target=4)
    assert [r["command_line"] for r in mal] == ["m1", "m2", "m3"]
    assert len(ben) == 4 and all(r["label"] == "benign" for r in ben)


def test_finalize_backfills_and_trims():
    cands = _cands(5, 8)
    # too few malicious (and one wrong-label id), too many benign
    mal, ben = picker.finalize_selection([1, 6], [6, 7, 8, 9, 10, 11], cands,
                                         mal_target=3, ben_target=4)
    assert len(mal) == 3 and all(r["label"] == "malicious" for r in mal)
    assert mal[0]["command_line"] == "m1"  # valid pick kept first
    assert len(ben) == 4
    # ids appear once across both lists
    all_ids = [r["id"] for r in mal + ben]
    assert len(all_ids) == len(set(all_ids))


def test_finalize_raises_when_insufficient():
    cands = _cands(2, 8)
    with pytest.raises(picker.PickerError):
        picker.finalize_selection([1], [3, 4], cands, mal_target=3, ben_target=4)
