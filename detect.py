"""Rule-based detection engine. Each finding is mapped to MITRE ATT&CK.
Usage: python detect.py            (prints JSON findings)
Try writing your own rules and see what the engine misses!
"""
import collections
import datetime as dt
import json
import re
import urllib.parse

AUTH = "sample_logs/auth.log"
WEB = "sample_logs/web_access.log"

FAIL = re.compile(r"^(\w+\s+\d+ [\d:]+) \S+ sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+)")
OK = re.compile(r"^(\w+\s+\d+ [\d:]+) \S+ sshd\[\d+\]: Accepted (\w+) for (\S+) from (\S+)")
SUDO = re.compile(r"sudo: (\S+) : .*COMMAND=(.*)$")
WEBLINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]*" (\d{3}) (\d+) "[^"]*" "([^"]*)"')

SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|gobuster|dirbuster|masscan|wpscan", re.I)
SQLI = re.compile(r"union\s+select|or\s+'?1'?='?1|sleep\(|information_schema|--\s*$", re.I)
SUSP_SUDO = re.compile(r"useradd|adduser|crontab|curl .*-o|wget |chmod \+s|nc -e|/tmp/\.", re.I)


def ts(s):
    return dt.datetime.strptime("2026 " + " ".join(s.split()), "%Y %b %d %H:%M:%S")


def detect_ssh():
    findings, fails, ok = [], collections.defaultdict(list), []
    sudo_events = []
    for line in open(AUTH):
        line = line.rstrip()
        if m := FAIL.match(line):
            fails[m.group(3)].append((ts(m.group(1)), m.group(2), line))
        elif m := OK.match(line):
            ok.append((ts(m.group(1)), m.group(3), m.group(4), line))
        elif m := SUDO.search(line):
            sudo_events.append((m.group(1), m.group(2), line))
    for ip, ev in fails.items():
        ev.sort()
        users = {u for _, u, _ in ev}
        span = (ev[-1][0] - ev[0][0]).total_seconds()
        if len(ev) >= 10 and span <= 600:
            kind = "Password spraying" if len(users) >= 4 else "Brute force"
            findings.append(dict(rule="ssh_bruteforce", severity="high", mitre="T1110", title=f"{kind} from {ip}",
                                 src_ip=ip, count=len(ev), distinct_users=len(users), evidence=[e[2] for e in ev[:3]]))
            for t, user, oip, line in ok:
                if oip == ip and t >= ev[-1][0]:
                    findings.append(dict(rule="ssh_success_after_bruteforce", severity="critical", mitre="T1078",
                                         title=f"Successful login for '{user}' from {ip} after {len(ev)} failures",
                                         src_ip=ip, evidence=[line]))
    for user, cmd, line in sudo_events:
        if SUSP_SUDO.search(cmd):
            findings.append(dict(rule="suspicious_sudo", severity="high", mitre="T1136/T1053/T1105",
                                 title=f"Suspicious privileged command by {user}", evidence=[line]))
    return findings


def detect_web():
    findings, by_ip = [], collections.defaultdict(list)
    for line in open(WEB):
        if m := WEBLINE.match(line):
            ip, _, method, path, status, _, ua = m.groups()
            by_ip[ip].append((method, urllib.parse.unquote(path), status, ua, line.rstrip()))
    for ip, reqs in by_ip.items():
        scan = [r for r in reqs if SCANNER_UA.search(r[3])]
        if scan:
            findings.append(dict(rule="scanner_ua", severity="medium", mitre="T1595", title=f"Scanner activity from {ip} ({scan[0][3]})",
                                 src_ip=ip, count=len(scan), evidence=[r[4] for r in scan[:3]]))
        sq = [r for r in reqs if SQLI.search(r[1])]
        if sq:
            findings.append(dict(rule="sqli_attempt", severity="high", mitre="T1190", title=f"SQL injection attempts from {ip}",
                                 src_ip=ip, count=len(sq), evidence=[r[4] for r in sq[:3]]))
        up = [r for r in reqs if r[0] == "POST" and "upload" in r[1] and r[2] == "200"]
        sh = [r for r in reqs if re.search(r"/uploads/.*\.php\?(cmd|c|exec)=", r[1]) and r[2] == "200"]
        if up and sh:
            findings.append(dict(rule="webshell", severity="critical", mitre="T1505.003", title=f"Likely web shell used by {ip}",
                                 src_ip=ip, count=len(sh), evidence=[up[0][4]] + [r[4] for r in sh[:3]]))
    return findings


def run():
    return detect_ssh() + detect_web()


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
