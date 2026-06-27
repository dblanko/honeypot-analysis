#!/usr/bin/env python3
"""
analyze_cowrie.py — Master statistics across the last 10 days of logs.
Run this first when you connect to the honeypot to get a quick overview.
"""
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_DIR = '/home/cowrie/cowrie/var/log/cowrie'

# ── Collect logs from last 10 days ──────────────────────────────────────────
files = []
now = datetime.now()
cutoff = now - timedelta(days=10)
for fname in os.listdir(LOG_DIR):
    if fname.startswith('cowrie.json'):
        path = os.path.join(LOG_DIR, fname)
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        if mtime >= cutoff:
            files.append(path)
files.sort()
print(f'[+] Files found for analysis: {len(files)}')

# ── Counters ────────────────────────────────────────────────────────────────
logins   = Counter()
passwords= Counter()
ips      = Counter()
commands = Counter()
urls     = Counter()
downloads= []
sessions = set()

# ── Parse ───────────────────────────────────────────────────────────────────
for f in files:
    print(f'[+] Reading {f}')
    with open(f, 'r', errors='ignore') as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except:
                continue
            if 'src_ip' in event:
                ips[event['src_ip']] += 1
            if 'session' in event:
                sessions.add(event['session'])
            if event.get('eventid') == 'cowrie.login.success':
                logins[event.get('username', '')] += 1
                passwords[event.get('password', '')] += 1
            if event.get('eventid') == 'cowrie.command.input':
                commands[event.get('input', '')] += 1
            if event.get('eventid') == 'cowrie.session.file_download':
                downloads.append({
                    'src_ip': event.get('src_ip'),
                    'url':    event.get('url'),
                    'outfile':event.get('outfile'),
                    'shasum': event.get('shasum'),
                })
                urls[event.get('url')] += 1

# ── Report ──────────────────────────────────────────────────────────────────
print()
print('=' * 50)
print('  COWRIE 10-DAY REPORT')
print('=' * 50)
print(f'Unique sessions:  {len(sessions)}')
print(f'Unique IPs:       {len(ips)}')
print()
print('Top 10 IPs:')
for ip, cnt in ips.most_common(10):
    print(f'  {ip:<20} {cnt}')
print()
print('Top logins (successful):')
for u, cnt in logins.most_common(10):
    print(f'  {u:<20} {cnt}')
print()
print('Top passwords (successful):')
for pw, cnt in passwords.most_common(10):
    print(f'  {pw:<20} {cnt}')
print()
print('Top 10 commands:')
for cmd, cnt in commands.most_common(10):
    print(f'  {cnt:5d}  {cmd[:70]}')
print()
print('File downloads (showing first 10):')
for d in downloads[:10]:
    print(f'  IP={d["src_ip"]}  URL={d["url"]}  SHA256={d["shasum"]}')
print()
print('Top malware URLs:')
for url, cnt in urls.most_common(10):
    print(f'  {cnt:3d}  {url}')
print()
print('[+] Analysis complete.')
