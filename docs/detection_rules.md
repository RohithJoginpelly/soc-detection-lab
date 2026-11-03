# Detection Rules

Each rule lives in `detect.py`. Test status is covered by `tests/test_detect.py`.

## ssh_bruteforce (T1110)
- **Hypothesis:** many failed SSH logins from one IP in a short window indicate password guessing.
- **Data source:** `auth.log` (`sshd` Failed password lines).
- **Logic:** 10 or more failures from one source IP within 600 seconds. Labelled "password spraying" when 4 or more distinct usernames are tried.
- **False positives:** users mistyping passwords, shared NAT addresses, internal vulnerability scanners.
- **Limitations:** an attacker who waits more than 10 minutes between bursts, or spreads attempts across many IPs, evades it.
- **Response:** block the IP, check whether any account then logged in successfully.

## ssh_success_after_bruteforce (T1078)
- **Hypothesis:** a successful login from an IP that just brute-forced the server means the guessing worked.
- **Logic:** an `Accepted` login from the same IP after its last failure in a flagged burst.
- **False positives:** rare; a legitimate user behind the same NAT as an attacker.
- **Response:** treat as compromise: disable the account, kill sessions, review actions after login, rotate credentials.

## suspicious_sudo (T1136, T1053, T1105)
- **Hypothesis:** privileged account creation, cron changes and payload downloads after login suggest persistence or tooling.
- **Logic:** sudo `COMMAND=` containing useradd/adduser, crontab, curl/wget downloads, SUID changes, or hidden `/tmp/.` paths.
- **False positives:** legitimate administration and deployment automation. Tune with an allowlist of known admin accounts.
- **Response:** verify with the account owner; if unexpected, investigate the session.

## scanner_ua (T1595)
- **Hypothesis:** automated scanners announce themselves in the User-Agent.
- **Logic:** User-Agent matches known scanner names.
- **False positives:** authorized security scans.
- **Limitations:** attackers trivially change the User-Agent, so absence of a match proves nothing.

## sqli_attempt (T1190)
- **Hypothesis:** SQL syntax in query strings indicates injection testing.
- **Logic:** URL-decoded requests matching UNION SELECT, OR 1=1 style, SLEEP(), information_schema.
- **False positives:** security testing, unusual but legitimate search input.
- **Limitations:** encoded or obfuscated payloads can evade simple pattern matching.

## webshell (T1505.003)
- **Hypothesis:** an upload followed by requests to an uploaded script with a command parameter means a web shell.
- **Logic:** successful POST to an upload endpoint plus successful GET to `/uploads/*.php?cmd=` style URLs from the same IP.
- **False positives:** very rare.
- **Response:** isolate the server, preserve evidence, remove the file, find the upload path and patch it.

## new_user_then_cron (T1136, T1053)
- **Hypothesis:** an attacker who gains access often creates a new account and schedules a job for it to keep access. Either action alone is common, but both within minutes is rare.
- **Data source:** `auth.log` (`sudo` command lines).
- **Logic:** a `useradd` or `adduser` command, followed by a `crontab -u <same user>` command within 300 seconds. The rule tracks each new user and fires only when the same account gets the job.
- **False positives:** an administrator legitimately setting up a service account and its scheduled job in one session. Tune with an allowlist of known admin accounts.
- **Limitations:** an attacker who waits more than 5 minutes, or who uses a different method for persistence (such as SSH keys or systemd timers), evades it.
- **Response:** verify with the account owner. If unexpected, disable the new account, remove its job and review the session that created it.
