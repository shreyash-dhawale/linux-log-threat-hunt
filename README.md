# Linux Log Threat Hunting

## Overview
A beginner-friendly SOC analyst project built in Kali Linux to detect SSH brute-force activity from a sample auth.log file. The project uses manual CLI triage and Python log parsing to identify repeated failed logins, suspicious IPs, invalid-user attempts, and successful logins after repeated failures.

## Tools
- Kali Linux
- Python3
- Pandas
- Linux commands: grep, awk, sort, uniq, egrep

## Project Structure
```text
linux-log-threat-hunt/
├── README.md
├── requirements.txt
├── data/
│   ├── raw/
│   │   └── auth_sample.log
│   └── processed/
│       └── parsed_events.csv
├── scripts/
│   ├── parse_auth_log.py
│   └── summarize_findings.py
├── outputs/
│   ├── suspicious_ips.csv
│   ├── successful_after_failures.csv
│   └── investigation_note.md
├── screenshots/
│   ├── 01-auth-log-failed-passwords.png
│   ├── 02-top-source-ips.png
│   └── 03-parser-execution.png
└── report/
    └── incident_report.md
```

## What this project detects
- Repeated failed SSH login attempts from the same IP.
- Multiple usernames targeted from one IP.
- Invalid user activity that may indicate username enumeration.
- Successful login after several failed attempts.

## How to run
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 scripts/parse_auth_log.py
python3 scripts/summarize_findings.py
```

## Output files
- parsed_events.csv
- suspicious_ips.csv
- successful_after_failures.csv
- investigation_note.md
- incident_report.md

## Note
This repository should use only sample or sanitized logs. Real usernames, real IPs, hostnames, credentials, and sensitive system details should not be uploaded to a public GitHub repository.
