#!/usr/bin/env python3
"""
generate_time_activity.py — Attack timing analysis.
Produces hourly and daily activity charts.
"""
import os
import json
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

LOG_DIR  = '/home/cowrie/cowrie/var/log/cowrie'
PLOTS_DIR= os.path.expanduser('~/malware_plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

timestamps = []

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
            if 'timestamp' in e:
                timestamps.append(e['timestamp'])

# ── Hourly chart ────────────────────────────────────────────────────────────
hours = Counter()
for ts in timestamps:
    try:
        hour = int(ts[11:13])   # 'YYYY-MM-DDTHH:MM:SS...'
        hours[hour] += 1
    except:
        pass

hour_labels = [str(h) for h in range(24)]
hour_values = [hours.get(h, 0) for h in range(24)]

plt.figure(figsize=(14, 5))
plt.bar(hour_labels, hour_values, color='steelblue')
plt.title('Attack Events by Hour (UTC)')
plt.xlabel('Hour (UTC)')
plt.ylabel('Event count')
plt.tight_layout()
out = os.path.join(PLOTS_DIR, 'activity_by_hour.png')
plt.savefig(out)
plt.close()
print(f'[+] Saved: {out}')

# ── Daily chart ─────────────────────────────────────────────────────────────
dates = Counter()
for ts in timestamps:
    try:
        dates[ts[:10]] += 1
    except:
        pass

sorted_dates = sorted(dates.items())
date_labels  = [d for d, _ in sorted_dates]
date_values  = [c for _, c in sorted_dates]

plt.figure(figsize=(14, 5))
plt.bar(date_labels, date_values, color='darkorange')
plt.title('Attack Events by Day')
plt.xlabel('Date')
plt.ylabel('Event count')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
out = os.path.join(PLOTS_DIR, 'activity_by_day.png')
plt.savefig(out)
plt.close()
print(f'[+] Saved: {out}')

# ── ASCII preview ───────────────────────────────────────────────────────────
print()
print('=== Hourly distribution (UTC) ===')
max_h = max(hour_values) if hour_values else 1
for h, v in enumerate(hour_values):
    bar = '#' * int(v / max_h * 40)
    print(f'  {h:02d}:00  {bar:<40} {v}')

print()
print('[+] Done.')
