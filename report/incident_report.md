# Incident Report: SSH Brute-Force Activity Analysis

## Objective
Analyze Linux authentication logs to identify brute-force SSH activity and summarize suspicious login behavior.

## Log Source
- Source: data/raw/auth_sample.log
- Platform: Kali Linux
- Log types reviewed: Failed password, Accepted password, Invalid user

## Investigation Steps
1. Copied auth.log into the project folder.
2. Used grep and awk to identify failed SSH login attempts.
3. Parsed the log with Python into structured CSV output.
4. Flagged suspicious IPs based on repeated failures and multiple targeted usernames.
5. Reviewed successful logins that occurred after repeated failures.

## Findings
- Top suspicious IPs:
- Most targeted usernames:
- Any accepted logins from previously noisy IPs:
- Any invalid-user enumeration activity:

## Risk
Repeated SSH login attempts may indicate brute-force or password-spray behavior. A successful login after many failures may indicate possible credential compromise.

## Remediation
- Enforce SSH key authentication where possible.
- Disable password authentication if feasible.
- Restrict SSH exposure to trusted IPs.
- Add rate limiting or blocking controls such as Fail2ban.
- Monitor auth logs continuously for repeated failures.