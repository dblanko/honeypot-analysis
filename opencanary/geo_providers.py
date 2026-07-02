import maxminddb
from collections import Counter

reader    = maxminddb.open_database("/var/lib/GeoIP/GeoLite2-ASN.mmdb")
providers = Counter()

with open("unique_ips.txt") as f:
    for ip in f:
        ip = ip.strip()
        if not ip: continue
        try:
            rec = reader.get(ip)
            org = rec.get("autonomous_system_organization", "UNK")
        except:
            org = "UNK"
        providers[org] += 1
reader.close()

print("Provider;Count")
for org, cnt in providers.most_common():
    print(f"{org};{cnt}")
