import json
from collections import Counter

LOGFILE = "period.json"
LOGTYPE_NAMES = {
    14001: "RDP", 17001: "Redis", 11001: "NTP",
    13001: "SNMP", 12001: "VNC",  16001: "Git", 1001: "System"
}
counts = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        lt = event.get("logtype")
        if lt: counts[LOGTYPE_NAMES.get(lt, str(lt))] += 1

print("Service;Count")
for svc, cnt in counts.most_common():
    print(f"{svc};{cnt}")
