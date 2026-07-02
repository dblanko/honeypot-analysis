import json
import geoip2.database
from collections import Counter

LOGFILE   = "period.json"
MMDB_PATH = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
countries = Counter()
continents = Counter()
ip_cache = {}
total = errors = 0

with geoip2.database.Reader(MMDB_PATH) as reader:
    with open(LOGFILE) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: event = json.loads(line)
            except: continue
            src = event.get("src_host")
            if not src: continue
            total += 1
            if src in ip_cache:
                country, continent = ip_cache[src]
            else:
                try:
                    resp = reader.country(src)
                    country   = resp.country.name or "Unknown"
                    continent = resp.continent.name or "Unknown"
                except:
                    country = continent = "Unknown"
                    errors += 1
                ip_cache[src] = (country, continent)
            countries[country] += 1
            continents[continent] += 1

print(f"Total: {total}, Unique IPs: {len(ip_cache)}, Unknown: {errors}")
print("\n=== TOP COUNTRIES (by events) ===")
for c, n in countries.most_common(20):
    print(f"  {c:<30} {n:>8} ({n/total*100:.1f}%)")
print("\n=== DISTRIBUTION BY CONTINENT ===")
for c, n in continents.most_common():
    print(f"  {c:<20} {n:>8} ({n/total*100:.1f}%)")
print("\n=== TOP COUNTRIES BY UNIQUE IP ===")
ip_by_country = Counter()
for ip, (country, _) in ip_cache.items(): ip_by_country[country] += 1
for c, n in ip_by_country.most_common(20):
    print(f"  {c:<30} {n:>5} unique IPs")
