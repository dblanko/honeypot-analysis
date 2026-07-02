import json
from collections import Counter

LOGFILE = "period.json"
total_events = 0
logtypes = Counter()
days = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        total_events += 1
        logtypes[event.get("logtype", "unknown")] += 1
        utc = event.get("utc_time")
        if utc: days[utc.split(" ")[0]] += 1

print("Total events:", total_events)
print("\nLogtype distribution:")
for lt, cnt in logtypes.most_common():
    print(f"  {lt}: {cnt}")
print("\nDistribution by days:")
for day, cnt in sorted(days.items()):
    print(f"  {day}: {cnt}")
