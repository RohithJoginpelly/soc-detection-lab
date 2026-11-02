import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def findings(tmp_path_factory):
    work = tmp_path_factory.mktemp("lab")
    subprocess.run([sys.executable, str(ROOT / "generate_logs.py")], cwd=work, check=True)
    old = os.getcwd()
    os.chdir(work)
    sys.path.insert(0, str(ROOT))
    try:
        import detect

        importlib.reload(detect)
        return detect.run()
    finally:
        os.chdir(old)


def rules(findings):
    return {f["rule"] for f in findings}


def test_all_expected_rules_fire(findings):
    expected = {
        "ssh_bruteforce",
        "ssh_success_after_bruteforce",
        "suspicious_sudo",
        "scanner_ua",
        "sqli_attempt",
        "webshell",
    }
    assert expected <= rules(findings)


def test_bruteforce_attributed_to_correct_ip(findings):
    bf = [f for f in findings if f["rule"] == "ssh_bruteforce"]
    assert len(bf) == 1
    assert bf[0]["src_ip"] == "203.0.113.45"
    assert bf[0]["count"] >= 60


def test_compromise_detected_for_deploy_account(findings):
    hit = [f for f in findings if f["rule"] == "ssh_success_after_bruteforce"]
    assert hit and "deploy" in hit[0]["title"]
    assert hit[0]["severity"] == "critical"


def test_webshell_attributed_to_correct_ip(findings):
    hit = [f for f in findings if f["rule"] == "webshell"]
    assert hit and hit[0]["src_ip"] == "198.51.100.77"


def test_no_false_positives_for_internal_users(findings):
    # bob's harmless typos come from 10.0.0.22 and must not alert
    assert not any(f.get("src_ip", "").startswith("10.0.0.") for f in findings)


def test_every_finding_has_mitre_and_evidence(findings):
    for f in findings:
        assert f["mitre"]
        assert f["evidence"]
