"""The synthetic case generator unblocks rules/report work before any real
parser exists (spec 2.10). Deterministic under a seed; contains a scripted
attack whose ground truth is emitted alongside."""
import json

from lfa import db
from lfa.schema import CATEGORIES, validate

from tools.make_synthetic_case import build_case


def test_build_case_deterministic(tmp_path):
    p1 = tmp_path / "a.db"
    p2 = tmp_path / "b.db"
    gt1 = build_case(p1, seed=42)
    gt2 = build_case(p2, seed=42)
    assert gt1 == gt2

    from lfa import canonical

    c1 = db.open_case(p1)
    c2 = db.open_case(p2)
    h1 = canonical.export_json(c1, tmp_path / "a.json")
    h2 = canonical.export_json(c2, tmp_path / "b.json")
    assert h1 == h2  # Gate G0
    c1.close()
    c2.close()


def test_case_is_plausible_and_valid(tmp_path):
    path = tmp_path / "case.db"
    build_case(path, seed=7)
    conn = db.open_case(path)
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert n >= 2000

    cats = {r[0] for r in conn.execute("SELECT DISTINCT category FROM events")}
    assert cats >= CATEGORIES - {"environment"}
    conn.close()


def test_attack_ground_truth_present(tmp_path):
    path = tmp_path / "case.db"
    ground_truth = build_case(path, seed=7)
    kinds = {g["kind"] for g in ground_truth}
    assert kinds == {
        "brute_force_burst",
        "break_in_success",
        "account_created",
        "privilege_granted",
        "authorized_key_added",
        "cron_job_added",
        "history_wiped",
    }
    conn = db.open_case(path)
    # the brute-force burst really exists in the data
    burst = next(g for g in ground_truth if g["kind"] == "brute_force_burst")
    n_failed = conn.execute(
        "SELECT COUNT(*) FROM events WHERE subcategory='failed_login' AND source_ip=?",
        (burst["source_ip"],),
    ).fetchone()[0]
    assert n_failed >= 5
    conn.close()


def test_ground_truth_written_next_to_db(tmp_path):
    path = tmp_path / "case.db"
    expected = build_case(path, seed=7)
    gt_path = tmp_path / "case.ground_truth.json"
    assert gt_path.exists()
    assert json.loads(gt_path.read_text(encoding="utf-8")) == expected
