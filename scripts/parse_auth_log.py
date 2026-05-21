import os
import re
import pandas as pd
from collections import defaultdict

INPUT_FILE = 'data/raw/auth_sample.log'
PARSED_OUT = 'data/processed/parsed_event.csv'
SUSPICIOUS_IPS_OUT = 'outputs/suspicious_ips.csv'
SUCCESS_AFTER_FAILURE_OUT = 'outputs/success_after_failure.csv'

os.makedirs('data/processed', exist_ok=True)
os.makedirs('outputs', exist_ok=True)

failed_re = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]: Failed password for (?:(invalid user) )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

accepted_re = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]: Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

invalid_user_re = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

events = []
with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()

        m = failed_re.search(line)
        if m:
            events.append({
                'timestamp' : m.group('timestamp'),
                'host' : m.group('host'),
                'event_type' : 'failed_password',
                'username' : m.group('user'),
                'source_ip' : m.group('ip'),
                'raw_line' : line
            })
            continue

        m = accepted_re.search(line)
        if m:
            events.append({
                'timestamp' : m.group('timestamp'),
                'host' : m.group('host'),
                'event_type' : 'accepted_password',
                'username' : m.group('user'),
                'source_ip' : m.group('ip'),
                'raw_line' :line
            })
            continue

        m =invalid_user_re.search(line)
        if m:
            events.append({
                'timestamp' : m.group('timestamp'),
                'host' : m.group('host'),
                'event_type' : 'invalid_user',
                'username' : m.group('user'),
                'source_ip' : m.group('ip'),
                'raw_line' :line
            })

df = pd.DataFrame(events)

if df.empty:
    print("No matching SSH authentication events found")
    raise SystemExit(0)

df.to_csv(PARSED_OUT, index=False)

failed_df = df[df['event_type'] == 'failed_password']
accepted_df = df[df['event_type'] == 'accepted_password']

ip_fail_counts = failed_df.groupby('source_ip').size().reset_index(name='failed_attempts')
ip_user_counts = failed_df.groupby('source_ip')["username"].nunique().reset_index(name='unique_usernames')

suspicious = ip_fail_counts.merge(ip_user_counts, on='source_ip', how='left')
suspicious = suspicious[
    (suspicious['failed_attempts'] >= 5) |
    (suspicious['unique_usernames'] >= 3)
].sort_values(by='failed_attempts', ascending=False)

suspicious.to_csv(SUSPICIOUS_IPS_OUT, index=False)

failed_ips = set(
    failed_df.groupby('source_ip').size()[lambda x: x >= 3].index
)

success_after_failure = accepted_df[accepted_df['source_ip'].isin(failed_ips)].copy()
success_after_failure.to_csv(SUCCESS_AFTER_FAILURE_OUT, index=False)

print(f"Parsed events saved to: {PARSED_OUT}")
print(f"Suspicious IPs saved to: {SUSPICIOUS_IPS_OUT}")
print(f"Success-after-failure events saved to: {SUCCESS_AFTER_FAILURE_OUT}")
