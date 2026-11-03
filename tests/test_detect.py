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


def test_new_user_then_cron_correlation(findings):
    hit = [f for f in findings if f["rule"] == "new_user_then_cron"]
    assert len(hit) == 1
    assert "svc_backup" in hit[0]["title"]


def _write_spray_log(tmp_path, users, minutes, ip="198.51.100.200"):
    lines = [
        f"Nov  1 05:{m:02d}:00 web01 sshd[1]: Failed password for invalid user {u} from {ip} port 4000 ssh2"
        for m, u in zip(minutes, users)
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n")
    return str(log)


def test_slow_spray_catches_low_and_slow_attacker(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    import detect

    monkeypatch.setattr(detect, "AUTH", _write_spray_log(tmp_path, ["root", "admin", "oracle", "test", "ubuntu"], [0, 5, 10, 15, 20]))
    found = detect.detect_slow_spray()
    assert len(found) == 1
    assert found[0]["src_ip"] == "198.51.100.200"


def test_slow_spray_ignores_few_usernames(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    import detect

    monkeypatch.setattr(detect, "AUTH", _write_spray_log(tmp_path, ["root", "admin", "root", "admin", "root"], [0, 5, 10, 15, 20]))
    assert detect.detect_slow_spray() == []


def _write_web_log(tmp_path, hits, ip="198.51.100.150"):
    import datetime as dt

    base = dt.datetime(2026, 11, 1, 4, 0, 0)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0"
    lines = [
        f'{ip} - - [{(base + dt.timedelta(seconds=s)).strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {p} HTTP/1.1" 404 196 "-" "{ua}"'
        for s, p in hits
    ]
    log = tmp_path / "web_access.log"
    log.write_text("\n".join(lines) + "\n")
    return str(log)


def test_404_burst_catches_scanner_with_normal_user_agent(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    import detect

    hits = [(0, "/a"), (1, "/b"), (2, "/c"), (3, "/d"), (5, "/e"), (8, "/f")]
    monkeypatch.setattr(detect, "WEB", _write_web_log(tmp_path, hits))
    found = detect.detect_404_burst()
    assert len(found) == 1
    assert found[0]["src_ip"] == "198.51.100.150"


def test_404_burst_ignores_slow_misses(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    import detect

    hits = [(0, "/a"), (60, "/b"), (120, "/c"), (180, "/d"), (240, "/e"), (300, "/f")]
    monkeypatch.setattr(detect, "WEB", _write_web_log(tmp_path, hits))
    assert detect.detect_404_burst() == []


def test_404_burst_ignores_one_broken_link(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    import detect

    hits = [(i // 4, "/broken.png") for i in range(20)]
    monkeypatch.setattr(detect, "WEB", _write_web_log(tmp_path, hits))
    assert detect.detect_404_burst() == []
