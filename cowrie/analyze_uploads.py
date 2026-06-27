#!/usr/bin/env python3
"""
analyze_uploads.py — SFTP upload analysis.
Identifies operator-pushed tools (e.g. RedTail SFTP sessions).
"""
import os
import json
import csv
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

LOG_DIR  = '/home/cowrie/cowrie/var/log/cowrie'
PLOTS_DIR= '/home/honeypotuser/malware_plots'
os.makedirs(PLOTS_DIR, exist_ok=True)

events = []

files = sorted([
    os.path.join(LOG_DIR, f)
    for f in os.listdir(LOG_DIR)
    if f.startswith('cowrie.json')
])

for f in files:
    with open(f, 'r', errors='ignore') as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except:
                continue
            if e.get('eventid') == 'cowrie.session.file_upload':
                events.append({
                    'timestamp': e.get('timestamp', ''),
                    'src_ip':    e.get('src_ip', ''),
                    'filename':  e.get('filename', ''),
                    'sha256':    e.get('shasum', ''),
                    'session':   e.get('session', ''),
                })

print(f'[+] Total upload events: {len(events)}')

# ── Save JSON + CSV ─────────────────────────────────────────────────────────
with open('malware_uploads.json', 'w') as f:
    json.dump(events, f, indent=2)

with open('malware_uploads.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['timestamp','src_ip','filename','sha256','session'])
    w.writeheader()
    w.writerows(events)

# ── Charts ──────────────────────────────────────────────────────────────────
filenames = Counter(e['filename'] for e in events)
ips       = Counter(e['src_ip']   for e in events)

if filenames:
    labels, values = zip(*filenames.most_common(15))
    plt.figure(figsize=(12, 8))
    plt.barh(labels, values, color='teal')
    plt.title('Top uploaded filenames')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/uploads_top_filenames.png')
    plt.close()

if ips:
    labels, values = zip(*ips.most_common(15))
    plt.figure(figsize=(12, 6))
    plt.barh(labels, values, color='slateblue')
    plt.title('Top IPs uploading files')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/uploads_top_ips.png')
    plt.close()

dates = Counter()
for e in events:
    try:
        dt = datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00'))
        dates[str(dt.date())] += 1
    except:
        pass

if dates:
    sorted_d = sorted(dates.items())
    plt.figure(figsize=(12, 5))
    plt.bar([d for d, _ in sorted_d], [c for _, c in sorted_d], color='orange')
    plt.title('Upload activity by day')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/uploads_activity_by_day.png')
    plt.close()

print('[+] Files created: malware_uploads.json, malware_uploads.csv')
print(f'[+] Charts saved to {PLOTS_DIR}/')
