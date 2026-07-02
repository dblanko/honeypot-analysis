import json
from collections import Counter

LOGFILE = "period.json"
ips = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        src = event.get("src_host")
        if src: ips[src] += 1

print("Top 50 IPs by number of events:\n")
for ip, cnt in ips.most_common(50):
    print(f"{ip};{cnt}")
