import json
from collections import Counter, defaultdict

LOGFILE = "period.json"
LOGTYPE_NAMES = {14001:"RDP",17001:"Redis",11001:"NTP",
                 13001:"SNMP",12001:"VNC",16001:"Git"}
ip_services      = defaultdict(set)
ip_service_counts = defaultdict(Counter)

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        src = event.get("src_host")
        lt  = event.get("logtype")
        if not src or lt is None or lt == 1001: continue
        if lt in LOGTYPE_NAMES:
            ip_services[src].add(lt)
            ip_service_counts[src][lt] += 1

total_ips = len(ip_services)
single = sum(1 for s in ip_services.values() if len(s)==1)
triple = sum(1 for s in ip_services.values() if len(s)>=3)

print("IP × SERVICE CORRELATION")
print(f"  1 service:  {single:>5} IPs ({single/total_ips*100:.1f}%)")
print(f"  2 services: {total_ips-single-triple:>5} IPs")
print(f"  3+ services:{triple:>5} IPs ({triple/total_ips*100:.1f}%)")

print("\n── Top 20 universal IPs (most services) ──")
for ip, svcs in sorted(ip_services.items(), key=lambda x: -len(x[1]))[:20]:
    names = ", ".join(LOGTYPE_NAMES.get(lt,"?") for lt in sorted(svcs))
    total = sum(ip_service_counts[ip].values())
    print(f"  {ip:<22} {len(svcs):>3} svcs  {names:<25} {total:>7}")

rdp_redis = {ip for ip,s in ip_services.items() if 14001 in s and 17001 in s}
print(f"\n── IPs attacking both RDP and Redis: {len(rdp_redis)} ──")
for ip in sorted(rdp_redis)[:15]:
    r = ip_service_counts[ip][14001]
    d = ip_service_counts[ip][17001]
    print(f"  {ip:<22} RDP:{r:>7}  Redis:{d:>7}")

print("\n── Top specialists (1 service, max events) ──")
specialists = [(ip,svcs) for ip,svcs in ip_services.items() if len(svcs)==1]
spec_sorted = sorted(specialists, key=lambda x: -sum(ip_service_counts[x[0]].values()))[:10]
for ip, svcs in spec_sorted:
    lt = list(svcs)[0]
    n  = ip_service_counts[ip][lt]
    print(f"  {ip:<22} {LOGTYPE_NAMES.get(lt,lt):<8} {n:>7} events")
