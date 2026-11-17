# Dionaea

Analysis scripts for the Dionaea malware honeypot: connection statistics, payload analysis, infrastructure mapping and sample clustering.
Findings: [reports/wannacry_2026.md](reports/wannacry_2026.md)

## Data source

Dionaea logs to SQLite. The scripts query `connections`, `downloads`, `offers`, `mysql_commands`, `mssql_commands`, `dcerpcrequests`, `dcerpcbinds` and `logins` directly. Most scripts accept `--last-week`, `--last-month`, or `--from` / `--to` date ranges.

```
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
```

[`infrastructure_analysis.py`](infrastructure_analysis.py) and [`asn_analysis.py`](asn_analysis.py) also need a local GeoLite2-ASN database. Both autodetect common install paths or accept `--geo-asn`.

## Scripts

### Connection statistics

| Script | Purpose |
|--------|---------|
| `stats_basic.py` | Connections, unique IPs, connection types, protocols |
| `stats_by_event_type.py` | Per-protocol event counts and top attacker IPs |
| `exploit_stats.py` | Connections by protocol, transport, type |
| `timeline_hourly.py` | Accepted connections by hour |
| `timeline_by_protocol_full.py` | Hourly activity broken down per protocol |

### Attackers

| Script | Purpose |
|--------|---------|
| `geo_countries.py` | Attacker country distribution |
| `ip_top_attackers.py` | Top IPs ranked by combined event volume |
| `ip_persistence.py` | IPs returning across multiple days |
| `ip_service_correlation.py` | IPs hitting more than one service |
| `asn_analysis.py` | Attacking IPs grouped by ASN |
| `infrastructure_analysis.py` | ASN/protocol matrix, portscan patterns, first/last seen |

### Payloads

| Script | Purpose |
|--------|---------|
| `malware_stats.py` | Downloaded payload stats by MD5 and source domain |
| `malware_hashes.py` | Unique vs duplicate payload hashes |
| `malware_urls.py` | Download/offer URLs, normalised and ranked |
| `payload_timeline.py` | Payload downloads by day and hour |

### Binary analysis and clustering

| Script | Purpose |
|--------|---------|
| `hunter_1.py` | Fast static analysis of captured binaries (first 256 KB only): strings, entropy, PE timestamps, IOC matching. Classifies samples into families (WannaCry, Cryptominer, LinuxBot, Loader, RAT, Unknown), produces Top-N lists, writes JSON and Markdown reports. Designed for collections of tens of thousands of files. |
| `hunter_v2.py` | Groups analysed samples by family and clusters within each family by Jaccard similarity of extracted strings. Outputs a JSON graph (nodes + edges) and a Markdown cluster report. |

## Sample output

**stats_basic.py**
```
Total connections: 931752
Unique attacker IPs: 21425

Connection types:
 accept: 904563
 listen: 27185

Protocols:
 smbd: 738615
 mssqld: 74970
 httpd: 73974
 mysqld: 8491
```

**malware_hashes.py**
```
Total entries: 19999
Unique hashes: 2181

=== TOP HASHES ===
ae12bb54af31227017feffd9598a6f5e: 2897
996c2b2ca30180129c69352a3a3515e4: 1747
0ab2aeda90221832167e5127332dd702: 1327
```

**malware_urls.py**
```
Total URLs: 501, Unique: 19

=== TOP SOURCES ===
http://116.34.68.92:15151/exiles.exe: 300
http://156.238.237.180:3151/exiles.exe: 158
http://156.238.237.180:15151/exiles.exe: 12
http://211.149.211.225:65531/xxi.exe: 10
http://star.zcnet.net:7766/Server.exe: 6
http://45.92.1.50/rondo.qre.sh?=: 2
```

**hunter_v2.py**
```
[+] Families detected: 3
=== Family: WannaCry ===
Samples: 269
Clusters: 1
 - Cluster #1: 269 samples
   SHA256: 087169471437, af6d78b3226a, 212853304541 ...
=== Family: LinuxBot ===
Samples: 14
Clusters: 5
```

See [`reports/wannacry_2026.md`](reports/wannacry_2026.md) for the full cluster write-up: 269 distinct WannaCry samples captured live, all clustering into a single connected component.
