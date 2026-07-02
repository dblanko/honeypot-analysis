import json

LOGFILE = "period.json"
ips = set()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        src = event.get("src_host")
        if src:
            ips.add(src)

with open("unique_ips.txt", "w") as out:
    for ip in sorted(ips):
        out.write(ip + "\n")

print("Unique IP:", len(ips))
