import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, "-m", "evoting", *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8", cwd=ROOT, env=env)


def test_cli_demo_then_verify(tmp_path):
    p = tmp_path / "exp.json"
    d = run("demo", "--voters", "5", "--out", p, "--seed", "1")
    assert d.returncode == 0, d.stderr
    assert p.exists()
    v = run("verify", p)
    assert v.returncode == 0, v.stderr
    assert "A. VERIFICADO" in v.stdout
    assert "Clave de verificación de la autoridad:" in v.stdout


def test_cli_verify_tampered_exit_1(tmp_path):
    p = tmp_path / "exp.json"
    assert run("demo", "--voters", "4", "--out", p).returncode == 0
    d = json.loads(p.read_text(encoding="utf-8"))
    d["declared_result"] = d["declared_result"] + 1
    p.write_text(json.dumps(d), encoding="utf-8")
    v = run("verify", p)
    assert v.returncode == 1
