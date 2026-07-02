import json
from collections import Counter, defaultdict
from datetime import datetime

LOGFILE = "period.json"
LOGTYPE_NAMES = {14001:"RDP",17001:"Redis",11001:"NTP",
                 13001:"SNMP",12001:"VNC",16001:"Git"}
ip_events   = Counter()
ip_first    = {}
ip_last     = {}
ip_days     = defaultdict(set)
ip_logtypes = defaultdict(Counter)

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        src = event.get("src_host")
        utc = event.get("utc_time")
        lt  = event.get("logtype", 0)
        if not src or not utc: continue
        try: dt = datetime.strptime(utc[:19], "%Y-%m-%d %H:%M:%S")
        except: continue
        ip_events[src] += 1
        ip_days[src].add(utc[:10])
        ip_logtypes[src][lt] += 1
        if src not in ip_first or dt < ip_first[src]: ip_first[src] = dt
        if src not in ip_last  or dt > ip_last[src]:  ip_last[src]  = dt

total_ips = len(ip_events)
total_ev  = sum(ip_events.values())
print(f"Total unique IPs: {total_ips}  /  Total events: {total_ev}")
print(f"Average events/IP: {total_ev/total_ips:.1f}")

buckets = {"1":0,"2-9":0,"10-99":0,"100-999":0,"1k-9k":0,"10k+":0}
for n in ip_events.values():
    if n==1: buckets["1"]+=1
    elif n<10: buckets["2-9"]+=1
    elif n<100: buckets["10-99"]+=1
    elif n<1000: buckets["100-999"]+=1
    elif n<10000: buckets["1k-9k"]+=1
    else: buckets["10k+"]+=1
print("\n── Event count distribution ──")
for label, cnt in buckets.items():
    print(f"  {label:<10} {cnt:>5} IPs ({cnt/total_ips*100:.1f}%)")

multiday = {ip for ip,days in ip_days.items() if len(days)>=2}
print(f"\nMulti-day IPs: {len(multiday)} ({len(multiday)/total_ips*100:.1f}%)")

print("\n── Top 10 by longest active period ──")
durations = [(ip_last[ip]-ip_first[ip], ip) for ip in ip_first if ip in ip_last]
for delta, ip in sorted(durations, reverse=True)[:10]:
    d = delta.days; h = delta.seconds//3600
    n = ip_events[ip]
    svc = LOGTYPE_NAMES.get(ip_logtypes[ip].most_common(1)[0][0], "?")
    print(f"  {ip:<20} {n:>6} events  {d}d {h}h  {svc}")
