import json
from collections import Counter

LOGFILE = "period.json"
users = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        logdata = event.get("logdata", {})
        if isinstance(logdata, dict):
            username = logdata.get("USERNAME")
            if username: users[username] += 1

print("Top 10 USERNAME:\n")
for u, cnt in users.most_common(10):
    print(f"{u};{cnt}")
