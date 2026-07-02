from collections import Counter
import ipaddress

ips = []
with open("unique_ips.txt") as f:
    for line in f:
        ip = line.strip()
        if not ip: continue
        try: ips.append(ipaddress.ip_address(ip))
        except: continue

subnets_24 = Counter()
subnets_16 = Counter()
for ip in ips:
    subnets_24[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1
    subnets_16[str(ipaddress.ip_network(f"{ip}/16", strict=False))] += 1

print("Top /24 subnets:")
for net, count in subnets_24.most_common(20):
    print(f"{net};{count}")
print("\nTop /16 subnets:")
for net, count in subnets_16.most_common(20):
    print(f"{net};{count}")
