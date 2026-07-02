import json
from collections import Counter

LOGFILE = "period.json"
days = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        utc = event.get("utc_time")
        if utc: days[utc.split(" ")[0]] += 1

print("Date;Events")
for day, cnt in sorted(days.items()):
    print(f"{day};{cnt}")
