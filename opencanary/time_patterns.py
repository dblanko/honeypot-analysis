import json
from collections import Counter, defaultdict
from datetime import datetime

LOGFILE = "period.json"
LOGTYPE_NAMES = {14001:"RDP",17001:"Redis",11001:"NTP",13001:"SNMP",12001:"VNC"}
DAYS_EN = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
hours_all = Counter()
weekdays  = Counter()
hours_by_type = defaultdict(Counter)
day_hour_matrix = Counter()
total = 0

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        utc = event.get("utc_time")
        if not utc: continue
        try: dt = datetime.strptime(utc[:19], "%Y-%m-%d %H:%M:%S")
        except: continue
        total += 1
        h = dt.hour; wd = dt.weekday()
        lt = event.get("logtype", 0)
        hours_all[h] += 1
        weekdays[wd] += 1
        hours_by_type[lt][h] += 1
        day_hour_matrix[(wd, h)] += 1

print("TEMPORAL ATTACK PATTERNS (UTC)")
print("\n── UTC hour distribution ──")
mx = max(hours_all.values())
for h in range(24):
    n   = hours_all.get(h, 0)
    pct = n / total * 100
    bar = "█" * int(n / mx * 40)
    peak = " ◄ PEAK" if pct >= 7 else ""
    print(f"  {h:02d}:00 | {n:>7} | {pct:4.1f}% | {bar}{peak}")
print("\n── By day of week ──")
for wd in range(7):
    n = weekdays.get(wd, 0)
    print(f"  {DAYS_EN[wd]} | {n:>8} | {n/total*100:4.1f}%")
print("\n── Peak hour per service ──")
for lt in [14001, 17001, 11001, 13001, 12001]:
    hc = hours_by_type.get(lt)
    if not hc: continue
    ph = hc.most_common(1)[0][0]
    print(f"  {LOGTYPE_NAMES.get(lt,lt)}: peak {ph:02d}:00 UTC")
print("\n── Heatmap top 10 cells (weekday × UTC hour) ──")
for (wd, h), n in sorted(day_hour_matrix.items(), key=lambda x: -x[1])[:10]:
    print(f"  {DAYS_EN[wd]} {h:02d}:00 UTC  →  {n:>7} ({n/total*100:.1f}%)")
