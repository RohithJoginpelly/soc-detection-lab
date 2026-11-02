# Portfolio Guide: Git, Resume and Interviews

(You can delete this file before publishing, or keep it out of the repo by adding it to .gitignore.)

## 1. Publish to GitHub (from Kali)

```bash
cd ~/soc-lab
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
# put your real name in LICENSE first
git init
git add .
git commit -m "Initial commit: SOC detection lab with log generator and detections"
git branch -M main
```

1. On github.com click New repository. Name it `soc-detection-lab`. Leave "Add README" unticked.
2. Then:
```bash
git remote add origin https://github.com/RohithJoginpelly/soc-detection-lab.git
git push -u origin main
```
GitHub asks for a personal access token instead of a password (Settings, Developer settings, Personal access tokens).

3. In the repo page, add a description, add topics: `soc`, `blue-team`, `detection-engineering`, `mitre-attack`, `log-analysis`, `incident-response`, `python`, and pin the repo on your profile.

**Never commit your API key.** `.env` and `venv/` are already in `.gitignore`.

## 2. Make the history show real work
Commit as you finish each week, with clear messages, for example:
- `Add correlation rule: new account followed by cron change`
- `Tune brute-force threshold to remove internal false positives`
- `Add incident report for SSH takeover scenario`
- `Add Elastic dashboard screenshots`

Put your own completed reports in `docs/reports/` and screenshots in `docs/images/`. A repo with your own reports and tuned rules is far stronger than the starting code.

## 3. Resume bullets
**Only claim what you have actually done.** Replace bracketed values with your real numbers and delete bullets for weeks you have not finished.

**Project entry**
SOC Detection Lab | Python, MITRE ATT&CK, Elastic, Git | github.com/<you>/soc-detection-lab

- Built a SOC home lab that generates multi-stage intrusion logs (SSH brute force to persistence; SQL injection to web shell) and detects them with [6] MITRE ATT&CK-mapped rules.
- Engineered and tuned [N] detection rules, reducing false positives by [describe your change], and validated them with [N] automated pytest tests and GitHub Actions CI.
- Integrated an LLM-assisted triage workflow that produces incident timelines, ATT&CK mapping and containment steps; verified outputs against raw logs and tested prompt-injection resilience.
- Investigated [2] incidents end to end and wrote reports covering timeline, root cause, evidence and recommendations.
- (After Week 5) Deployed Elasticsearch and Kibana, ingested logs and built [N] searches, a dashboard and an alert rule.
- (After Week 6 to 7) Ran Atomic Red Team tests against isolated VMs and measured detection coverage across [N] ATT&CK techniques.

**Skills line**
Log analysis, detection engineering, incident response, MITRE ATT&CK, SIEM (Elastic), Linux, Python, Git, SSH and web server logs.

## 4. Interview talking points
Prepare a 2-minute story and be able to answer:
1. *Walk me through one incident you investigated.* Use your own timeline and report.
2. *How did you decide a rule's threshold, and what false positives did you see?* Use the bob typos example.
3. *What does your detection miss?* Slow attacks, many source IPs, changed User-Agents.
4. *How did you use AI, and how did you check it?* You verified each claim against raw log lines and tested prompt injection.
5. *What would you do next with production data?* Real log sources, tuning, alert triage workflow, case management.

## 5. LinkedIn
Add the project under Projects, link the repo, and write a short post: what you built, one thing you learned (for example, the tradeoff between catching more attacks and creating more false alarms), and a screenshot of your dashboard.

## 6. Where to apply
Search for SOC Analyst (Tier 1), Security Analyst, Junior Detection Engineer and Cyber Defense Analyst roles. Pair this project with a certificate such as Security+ or Blue Team Level 1 if you can.
