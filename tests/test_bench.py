from evoting.bench import run_bench, write_results

KEYS = {"n", "ballot_bytes", "create_ms", "verify_ms_per_vote", "audit_ms"}


def test_bench_small(tmp_path):
    rows = run_bench(sizes=(1, 2), repeats=1)
    assert [r["n"] for r in rows] == [1, 2]
    for r in rows:
        assert set(r) == KEYS
        assert r["create_ms"] > 0 and r["verify_ms_per_vote"] > 0 and r["audit_ms"] > 0
    assert rows[0]["ballot_bytes"] == rows[1]["ballot_bytes"]
    out = tmp_path / "res"
    write_results(rows, out)
    md = (out / "metrics.md").read_text(encoding="utf-8")
    csv = (out / "metrics.csv").read_text(encoding="utf-8")
    assert "| 1 |" in md and "| 2 |" in md
    assert csv.splitlines()[0] == "n,ballot_bytes,create_ms,verify_ms_per_vote,audit_ms"
    assert len(csv.splitlines()) == 3
