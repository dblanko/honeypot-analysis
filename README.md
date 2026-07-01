# honeypot-analysis

Analysis scripts for Cowrie, OpenCanary, Dionaea, and Telnethoney honeypots.
Part of the [SSHLab Security Research Series](https://sshlab.eu) — six books on honeypot deployment and log analysis using real attack data from a live VPS.

---

## What this is

A single VPS running five honeypot sensors simultaneously:

- **Cowrie** — SSH/Telnet honeypot (credential harvesting, session logging)
- **OpenCanary** — multi-service honeypot (RDP, MSSQL, HTTP, SMB, MySQL)
- **Dionaea** — malware honeypot (full binary capture via SMB, MySQL, MSSQL)
- **Telnethoney** — custom IoT/Telnet honeypot (self-written, emulates BusyBox router)
- **Suricata** — network IDS (cross-sensor correlation)

All scripts in this repository run against real data collected from this deployment.
No synthetic datasets, no lab environments.

---

## Repository structure

```
cowrie/
    honeyfs_setup.sh         — corporate honeyfs setup (replaces default Cowrie filesystem)
    stats_basic.py           — total events, session count, basic overview
    top_ips.py                — top attacking IPs by session count
    credentials.py             — top usernames, passwords, and pairs
    commands.py                — top commands executed by attackers
    geo_countries.py           — geographic distribution of attacks
    timeline.py                 — attack timeline and hourly distribution
    session_analysis.py        — session depth, command sequences, attacker profiles
    download_analysis.py       — downloaded files, architecture detection, IOC extraction

dionaea/
    stats_basic.py              — connections, unique IPs, connection types, protocols
    stats_by_event_type.py      — per-protocol event counts and top attacker IPs
    geo_countries.py            — attacker country distribution
    ip_top_attackers.py         — top IPs ranked by combined event volume
    ip_persistence.py           — IPs returning across multiple days
    malware_stats.py            — downloaded payload stats by MD5 and source domain
    malware_hashes.py           — unique vs duplicate payload hashes
    malware_urls.py             — download/offer URLs, normalized and ranked
    payload_timeline.py         — payload downloads by day and hour
    exploit_stats.py            — connections by protocol, transport, type
    timeline_hourly.py          — accepted connections by hour
    timeline_by_protocol_full.py — hourly activity broken down per protocol
    ip_service_correlation.py   — IPs hitting more than one service
    asn_analysis.py             — attacking IPs grouped by ASN
    infrastructure_analysis.py  — ASN/protocol matrix, portscan patterns, first/last seen
    hunter.py                   — binary sample analysis, IOC/family classification, clustering
    reports/
        wannacry_2026.md        — cluster analysis of 269 WannaCry samples captured live

opencanary/
    stats_basic.py               — total events, logtype distribution, daily counts
    top_ips.py                    — top attacking IPs by event count
    top_usernames.py              — top USERNAME values across services
    geo_countries.py              — country/continent distribution by event volume
    extract_unique_ips.py         — dedup IP list for downstream GeoIP/ASN lookups
    geo_providers.py              — attacker distribution by ASN/org
    events_per_day.py             — daily event counts
    analyze_subnets.py            — top /24 and /16 attacker subnets
    attacks_per_service.py        — event counts by emulated service (RDP, VNC, Redis, NTP)
    rdp_logdata.py                 — RDP-specific username/credential field analysis
    time_patterns.py               — hourly/weekday attack distribution, per-service peaks
    ip_persistence.py              — event volume and active-period distribution per IP
    ip_service_correlation.py      — IPs attacking multiple emulated services

telnethoney/
    telnet.py                      — the honeypot itself (custom BusyBox router emulation)
    top_ips.py                      — top source IPs by event count
    top_countries.py                — top countries by event count
    top_asn.py                      — top autonomous systems by event count
    hosting_vs_residential.py       — IP classification (hosting/VPN, residential, Tor)
    telnet_credentials.py           — top usernames, passwords, credential pairs
    telnet_commands.py              — top commands by frequency
    telnet_attacker_profiles.py     — behavioural classification (downloader, loader, etc.)
    telnet_sessions.py              — full command sequences per IP
    telnet_commands_by_hour.py      — command activity timeline
    delivery_methods.py             — payload delivery technique detection (wget, tftp, etc.)
    telnet_binary_handshake.py      — non-text/binary connection attempts
    architectures.py                — target CPU architectures referenced in commands

suricata/      — coming soon
```

---

## Cowrie — corporate honeyfs

The default Cowrie filesystem looks like a generic Debian install — experienced attackers recognise it immediately. `honeyfs_setup.sh` replaces it with a simulated corporate cluster environment including Prometheus, Jenkins, Terraform, Kafka, Zookeeper, Ceph, PostgreSQL, MySQL, Nginx, and Docker artefacts.

**Path constants** in all scripts match the standard Cowrie deployment path:
```
LOG_DIR = '/home/cowrie/cowrie/var/log/cowrie'
```
If your installation uses a different path, edit this constant at the top of each script before running.

### Sample output

**credentials.py**
```
=== Top Usernames ===
root          4821
admin         1205
ubuntu         342
pi             289

=== Top Passwords ===
123456        1834
admin          967
password       441

=== Top Username:Password Pairs ===
root:123456    892
admin:admin    654
```

**geo_countries.py**
```
=== Top Countries (by sessions) ===
China              8421  (34.1%)
United States      3205  (13.0%)
Russia             2891  (11.7%)
Netherlands        1654   (6.7%)
Germany             987   (4.0%)
```

---

## Dionaea — malware capture and clustering

Dionaea logs to a SQLite database (`dionaea.sqlite`); the analysis scripts query `connections`, `downloads`, `offers`, `mysql_commands`, `mssql_commands`, `dcerpcrequests`, `dcerpcbinds`, and `logins` directly. Most scripts accept `--last-week`, `--last-month`, or `--from`/`--to` date ranges.

**Path constant** in all scripts:
```
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
```

`infrastructure_analysis.py` and `asn_analysis.py` additionally require a local GeoLite2-ASN database; both autodetect common install paths or accept `--geo-asn`.

`hunter.py` is a separate tool for analysing captured binaries directly (not the SQLite DB): it reads the first 256 KB of each sample, extracts strings, computes entropy and PE timestamps where applicable, matches IOC patterns, classifies samples into families (WannaCry, Cryptominer, LinuxBot, Loader, RAT, Unknown), clusters same-family samples by Jaccard similarity of extracted strings, and writes both a JSON graph and a Markdown report. It is built for large collections (tens of thousands of files) since it only reads partial file content.

### Sample output

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

**hunter.py**
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

See [`dionaea/reports/wannacry_2026.md`](dionaea/reports/wannacry_2026.md) for the full cluster writeup: 269 distinct WannaCry samples captured live, all clustering into a single connected component.

---

## OpenCanary — multi-service emulation

OpenCanary writes a single JSON-lines log (`opencanary.log`); scripts work against a time-sliced extract (`period.json`) produced with a simple `awk` range filter. Each script reads the file once and aggregates by `logtype`, `src_host`, or fields inside `logdata`.

**Path constant** in all scripts:
```
LOGFILE = "period.json"
```

`geo_countries.py` and `geo_providers.py` require local GeoLite2-Country and GeoLite2-ASN databases.

### Sample output

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

---

## Telnethoney — custom IoT/Telnet honeypot

Telnethoney (`telnet.py`) is a self-written honeypot, not a third-party project. It emulates a BusyBox-based IoT router: fake `ps`, `top`, `df`, `ifconfig`, `uname`, `/proc/cpuinfo`, working `echo >`/`echo >>` file redirection, and a minimal HTTP server that serves fake binaries to scripted downloaders. Every login attempt, command, and HTTP request is logged to a single JSON-lines file, enriched at write time with GeoIP/ASN lookups and an IP classification (hosting/VPN, residential, Tor, unknown).

**Path constant** in all scripts:
```
LOGFILE = 'telnethoney.json'
```

### Sample output

**telnet_credentials.py**
```
=== Top Usernames ===
root 32817
admin 5456
user 755

=== Top Passwords ===
123456 990
admin 632
111111 246
```

**telnet_attacker_profiles.py**
```
=== Attacker Profiles ===
Unknown: 84311
Interactive Shell: 72247
Credential Brute Force: 57341
Botnet Loader: 17817
HTTP Scanner: 5491
```

**delivery_methods.py**
```
=== Delivery Methods ===
wget: 236
curl: 124
busybox wget: 93
nc: 72
tftp: 48
```

---

## Books

These scripts are the maintained, tested versions of the analysis tools documented in the Security Research Series.
Minor differences from the print appendices reflect path corrections and enhancements made after publication.

| Book | Honeypot | Scripts |
|------|----------|---------|
| [Book 1 — Cowrie SSH Honeypot](https://leanpub.com/cowrie) | Cowrie | `cowrie/` |
| [Book 2 — OpenCanary](https://leanpub.com/opencanary-honeypot) | OpenCanary | `opencanary/` |
| [Book 3 — Dionaea Malware Honeypot](https://leanpub.com/dionaeahoneypot) | Dionaea | `dionaea/` |
| [Book 4 — Telnethoney IoT](https://leanpub.com/telnethoney) | Telnethoney | `telnethoney/` |
| [Book 5 — Suricata](https://leanpub.com/suricata) | Suricata | — |
| [Book 6 — Correlation](https://leanpub.com/correlation) | All sensors | — |

Full series: [Security Research Series](https://leanpub.com/b/securityresearchseries)

---

## License

MIT — see [LICENSE](LICENSE)
Scripts may be used freely. If you use them in research or writing, a mention of SSHLab Research is appreciated.


