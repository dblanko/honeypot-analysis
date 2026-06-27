#!/usr/bin/env python3
"""
analyze_creds_commands.py — Credential and command frequency analysis.
Ranked tables ready for copy-paste into incident reports.
"""
import json
import os
from collections import Counter

LOG_DIR = '/home/cowrie/cowrie/var/log/cowrie'

files = sorted([
    os.path.join(LOG_DIR, f)
    for f in os.listdir(LOG_DIR)
    if f.startswith('cowrie.json')
])

logins   = Counter()
passwords= Counter()
pairs    = Counter()
commands = Counter()

for f in files:
    with open(f, 'r', errors='ignore') as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except:
                continue
            if e.get('eventid') == 'cowrie.login.success':
                u = e.get('username', '')
                p = e.get('password', '')
                logins[u]    += 1
                passwords[p] += 1
                pairs[(u, p)]+= 1
            if e.get('eventid') == 'cowrie.command.input':
                commands[e.get('input', '')] += 1

W = 60  # column width for command truncation

print(f'\n=== Top Usernames ===')
for u, c in logins.most_common(20):
    print(f'  {c:6d}  {u}')

print(f'\n=== Top Passwords ===')
for pw, c in passwords.most_common(20):
    print(f'  {c:6d}  {pw}')

print(f'\n=== Top Username:Password Pairs ===')
for (u, p), c in pairs.most_common(20):
    print(f'  {c:6d}  {u}:{p}')

print(f'\n=== Top Commands ===')
for cmd, c in commands.most_common(30):
    print(f'  {c:6d}  {cmd[:W]}')

# ── Save raw commands for analyze_chains.py ─────────────────────
raw_commands = []

for f in files:
    with open(f, 'r', errors='ignore') as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except:
                continue

            if e.get('eventid') == 'cowrie.command.input':
                raw_commands.append({
                    "src_ip": e.get("src_ip", ""),
                    "command": e.get("input", ""),
                    "timestamp": e.get("timestamp", ""),
                    "session": e.get("session", "")
                })

with open("malware_commands.json", "w") as f:
    json.dump(raw_commands, f, indent=2)

print("\n[+] Saved: malware_commands.json (raw commands)")
