# OpenCanary

Analysis scripts for OpenCanary multi-service emulation (RDP, VNC, Redis, NTP and others).
Findings: [reports/opencanary-findings.md](reports/opencanary-findings.md)

## Data source

OpenCanary writes a single JSON-lines log (`opencanary.log`). The scripts work against a time-sliced extract (`period.json`) produced with a simple `awk` range filter. Each script reads the file once and aggregates by `logtype`, `src_host`, or fields inside `logdata`.

```
LOGFILE = "period.json"
```

[`geo_countries.py`](geo_countries.py) and [`geo_providers.py`](geo_providers.py) require local GeoLite2-Country and GeoLite2-ASN databases.

## Scripts

| Script | Purpose |
|--------|---------|
| `stats_basic.py` | Total events, logtype distribution, daily counts |
| `events_per_day.py` | Daily event counts |
| `top_ips.py` | Top attacking IPs by event count |
| `top_usernames.py` | Top USERNAME values across services |
| `extract_unique_ips.py` | Deduplicated IP list for downstream GeoIP/ASN lookups |
| `geo_countries.py` | Country/continent distribution by event volume |
| `geo_providers.py` | Attacker distribution by ASN/org |
| `analyze_subnets.py` | Top /24 and /16 attacker subnets |
| `attacks_per_service.py` | Event counts by emulated service |
| `rdp_logdata.py` | RDP-specific username/credential field analysis |
| `time_patterns.py` | Hourly/weekday attack distribution, per-service peaks |
| `ip_persistence.py` | Event volume and active-period distribution per IP |
| `ip_service_correlation.py` | IPs attacking multiple emulated services |

## Sample output

**top_usernames.py**
```
Top 10 USERNAME:
hello;1293911
test;428472
65;126004
Administrator;21688
```

**attacks_per_service.py**
```
Service;Count
RDP;3929226
VNC;76907
Redis;42418
NTP;549
```

**rdp_logdata.py**
```
Total RDP events: 3929226
USERNAME = null: 1979068 (50.4%)
USERNAME = empty: 39334 (1.0%)
USERNAME = value: 1910824 (48.6%)
PASSWORD present: 0
 >>> No passwords in RDP logs (NLA/CredSSP by design)
```

**ip_service_correlation.py**
```
IP × SERVICE CORRELATION
  1 service:   4387 IPs (96.1%)
  2 services:   177 IPs
  3+ services:    2 IPs (0.0%)

── Top 20 universal IPs (most services) ──
  65.49.1.142              3 svcs  NTP, RDP, Redis                16
  65.49.1.122              3 svcs  NTP, RDP, Redis                16
  65.49.1.182              2 svcs  RDP, Redis                      7
  18.116.101.220           2 svcs  RDP, Redis                     90
```
