#!/usr/bin/env python3
"""
attack_stats.py — Full Cowrie statistics report.
ASCII bar charts + matplotlib PNG timeline.
"""
import json, sys, re
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

LOG_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else \
           Path('/home/cowrie/cowrie/var/log/cowrie/cowrie.json')
OUT_PNG  = 'attack_stats.png'
BAR_W    = 40   # ASCII bar width

def bar(count, max_count, width=BAR_W):
    if max_count == 0: return ''
    return '█' * int(count / max_count * width)

# ── Parse ────────────────────────────────────────────────────────────────────
connections = 0
sessions    = set()
logins_fail = 0
logins_ok   = 0
cmd_count   = 0
dl_count    = 0
usernames   = Counter()
passwords   = Counter()
pairs       = Counter()
src_ips     = Counter()
hassh_map   = Counter()
hours       = Counter()
dates       = Counter()
campaigns   = defaultdict(lambda: {'ips': set(), 'urls': set()})
durations   = []
sess_start  = {}
sess_end    = {}

with LOG_PATH.open('r', errors='ignore') as f:
    for line in f:
        try: e = json.loads(line)
        except: continue
        eid = e.get('eventid', '')
        sid = e.get('session')
        ts_str = e.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z','+00:00'))
        except:
            ts = None
        if ts and sid:
            if sid not in sess_start or ts < sess_start[sid]: sess_start[sid] = ts
            if sid not in sess_end   or ts > sess_end[sid]:   sess_end[sid]   = ts
        if ts:
            hours[ts.hour] += 1
            dates[ts.date()] += 1
        if sid: sessions.add(sid)
        if 'src_ip' in e: src_ips[e['src_ip']] += 1
        if eid == 'cowrie.session.connect': connections += 1
        if eid == 'cowrie.login.failed':    logins_fail += 1
        if eid == 'cowrie.login.success':
            logins_ok += 1
            usernames[e.get('username','')] += 1
            passwords[e.get('password','')] += 1
            pairs[(e.get('username',''), e.get('password',''))] += 1
        if eid == 'cowrie.command.input':   cmd_count += 1
        if eid == 'cowrie.session.file_download':
            dl_count += 1
            sha = e.get('shasum')
            if sha:
                campaigns[sha]['ips'].add(e.get('src_ip',''))
                url = e.get('url')
                if url: campaigns[sha]['urls'].add(url)
        if eid == 'cowrie.client.kex':
            h8 = e.get('hassh','')[:8]
            if h8: hassh_map[h8] += 1

# Session durations
for sid in sessions:
    if sid in sess_start and sid in sess_end:
        dur = (sess_end[sid] - sess_start[sid]).total_seconds()
        durations.append(dur)

# ── Overview ─────────────────────────────────────────────────────────────────
print('=' * 60)
print('  COWRIE HONEYPOT — FULL STATISTICS REPORT')
print('=' * 60)
print(f'  Connections:      {connections:,}')
print(f'  Unique sessions:  {len(sessions):,}')
print(f'  Unique IPs:       {len(src_ips):,}')
print(f'  Login failures:   {logins_fail:,}')
print(f'  Login successes:  {logins_ok:,}')
print(f'  Commands logged:  {cmd_count:,}')
print(f'  Payload downloads:{dl_count:,}')
print()

# ── Top 10 credentials ───────────────────────────────────────────────────────
for label, counter in [('Usernames', usernames), ('Passwords', passwords)]:
    print(f'=== Top 10 {label} ===')
    mc = counter.most_common(10)
    mx = mc[0][1] if mc else 1
    for val, cnt in mc:
        print(f'  {cnt:6d} {bar(cnt,mx):<{BAR_W}}  {val[:50]}')
    print()

print('=== Top 10 Username:Password Pairs ===')
mc = pairs.most_common(10)
mx = mc[0][1] if mc else 1
for (u, p), cnt in mc:
    print(f'  {cnt:6d} {bar(cnt,mx):<{BAR_W}}  {u}:{p}')
print()

# ── Top IPs ──────────────────────────────────────────────────────────────────
print('=== Top 10 Source IPs ===')
mc = src_ips.most_common(10)
mx = mc[0][1] if mc else 1
for ip, cnt in mc:
    print(f'  {cnt:6d} {bar(cnt,mx):<{BAR_W}}  {ip}')
print()

# ── Hourly ASCII histogram ────────────────────────────────────────────────────
print('=== 24-Hour Activity (UTC) ===')
mx = max(hours.values()) if hours else 1
for h in range(24):
    cnt = hours.get(h, 0)
    print(f'  {h:02d}:00 {bar(cnt,mx):<{BAR_W}} {cnt:,}')
print()

# ── HASSH table ──────────────────────────────────────────────────────────────
KNOWN_HASSH = {
    '03a80b21': 'mdrfckr / libssh_0.11.1',
    '16443846': 'Go-scanner / SSH-2.0-Go',
    '015322ee': 'Mozi / libssh_0.11.3',
    'a7a87fbe': 'Gafgyt loader',
}
print('=== HASSH Fingerprints (top 10) ===')
for h8, cnt in hassh_map.most_common(10):
    name = KNOWN_HASSH.get(h8, 'Unknown')
    print(f'  {h8}  {cnt:6d}  {name}')
print()

# ── Campaign table ───────────────────────────────────────────────────────────
print('=== Download Campaigns (by SHA256) ===')
for sha, info in sorted(campaigns.items(), key=lambda x: -len(x[1]['ips'])):
    urls_str = ', '.join(sorted(info['urls']))[:60] or 'direct upload'
    print(f'  {sha[:16]}...  IPs:{len(info["ips"]):3d}  {urls_str}')
print()

# ── Session duration buckets ─────────────────────────────────────────────────
buckets = {'<1s': 0, '1-5s': 0, '5-30s': 0, '30s-2m': 0, '>2m': 0}
for d in durations:
    if d < 1:     buckets['<1s']   += 1
    elif d < 5:   buckets['1-5s']  += 1
    elif d < 30:  buckets['5-30s'] += 1
    elif d < 120: buckets['30s-2m']+= 1
    else:         buckets['>2m']   += 1
print('=== Session Duration Distribution ===')
mx = max(buckets.values()) if buckets else 1
for label, cnt in buckets.items():
    print(f'  {label:<8} {bar(cnt,mx):<{BAR_W}} {cnt:,}')
print()

# ── PNG chart ────────────────────────────────────────────────────────────────
sorted_dates = sorted(dates.items())
if sorted_dates:
    fig, ax = plt.subplots(figsize=(16, 5))
    ax.bar([str(d) for d, _ in sorted_dates],
           [c for _, c in sorted_dates], color='steelblue')
    ax.set_title('Cowrie — Daily Event Count')
    ax.set_xlabel('Date')
    ax.set_ylabel('Events')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(OUT_PNG)
    plt.close()
    print(f'[+] Chart saved: {OUT_PNG}')
