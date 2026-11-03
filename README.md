# SOC Detection Lab

A hands-on Security Operations Center (SOC) lab for practicing **attack detection, log analysis and incident investigation**, with an **LLM-assisted triage analyst** that produces incident reports.

It generates realistic synthetic logs containing two hidden multi-stage intrusions, detects them with MITRE ATT&CK-mapped rules, and uses an AI model to build an evidence-backed incident report. Everything is synthetic (RFC 5737 documentation IPs): no real systems or data are involved.

## What it demonstrates

- **Log analysis:** parsing SSH (`auth.log`) and web server (combined format) logs
- **Detection engineering:** rules for brute force, password spraying, login after brute force, suspicious privileged commands, scanner traffic, SQL injection and web shells, each mapped to MITRE ATT&CK
- **Incident investigation:** timelines, scoping, containment and eradication reasoning
- **AI-assisted triage:** LLM analyst with evidence citation and prompt-injection-aware design
- **Engineering practice:** automated tests (pytest) and CI (GitHub Actions)

## Architecture

```
generate_logs.py ──► sample_logs/ (auth.log, web_access.log)
                          │
                          ▼
                     detect.py  ──► findings (JSON, MITRE-mapped)
                          │
                          ▼
                    ai_triage.py ──► LLM incident report / interactive chat
```

## Scenarios (hidden in the generated logs)

| Scenario | Attacker IP | Chain | MITRE ATT&CK |
|---|---|---|---|
| SSH takeover | 203.0.113.45 | Password spray, valid account login, new user, scheduled job, payload download | T1110, T1078, T1136, T1053, T1105 |
| Web compromise | 198.51.100.77 | Nikto scan, SQL injection, file upload, web shell commands | T1595, T1190, T1505.003 |

## Detection rules

| Rule | Detects | Severity | Technique |
|---|---|---|---|
| `ssh_bruteforce` | 10+ failed logins from one IP within 10 minutes (spray if 4+ usernames) | High | T1110 |
| `ssh_success_after_bruteforce` | Successful login from an IP after a brute-force burst | Critical | T1078 |
| `suspicious_sudo` | Privileged account creation, cron changes, payload downloads | High | T1136, T1053, T1105 |
| `scanner_ua` | Known scanner User-Agents (Nikto, sqlmap, etc.) | Medium | T1595 |
| `sqli_attempt` | SQL injection patterns in URLs | High | T1190 |
| `webshell` | Upload followed by command execution via uploaded script | Critical | T1505.003 |

Full rule documentation (hypothesis, logic, false positives, limitations): [docs/detection_rules.md](docs/detection_rules.md).

## Quick start

```bash
git clone https://github.com/RohithJoginpelly/soc-detection-lab.git
cd soc-detection-lab
python3 generate_logs.py      # create synthetic logs
python3 detect.py             # run detections
```

AI triage (optional, requires an Anthropic API key):

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your-key
python3 ai_triage.py          # one-shot report
python3 ai_triage.py --chat   # interactive investigation
```

Run the tests:

```bash
pip install pytest
pytest
```

## Optional SIEM

`docker-compose.yml` starts Elasticsearch and Kibana on localhost for hands-on searching and dashboards. Security is disabled for lab convenience: never expose it beyond localhost.

## Using AI responsibly in a SOC

- The model proposes; the analyst verifies every claim against raw log lines.
- Logs are attacker-controlled input. The triage prompt treats them as untrusted data to reduce prompt-injection risk.
- Humans decide containment actions.
- Never send real customer or production data to an external AI service without approval.

## Investigation write-ups

See [docs/incident_report_template.md](docs/incident_report_template.md) for the report format used. Add your own completed reports under `docs/reports/`.
- [Incident 01: web01 intrusion](docs/reports/01-web01-intrusion.md)
## Roadmap

- [ ] Ship logs to Elastic/Kibana with Filebeat and build a dashboard
- [ ] Add Windows event and Sysmon log scenarios
- [ ] Add Wazuh, Zeek and Suricata telemetry
- [ ] Purple-team coverage table using Atomic Red Team on isolated VMs
- [ ] Sigma rule export

## Ethics and safety

All data is synthetic. Any attack simulation added later must run only against systems you own, on an isolated network.

## License

MIT, see [LICENSE](LICENSE).
