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
    honeyfs_setup.sh             — corporate honeyfs setup (replaces default Cowrie filesystem)
    stats_basic.py               — total events, session count, basic overview
    top_ips.py                   — top attacking IPs by session count
    credentials.py               — top usernames, passwords, and pairs
    commands.py                  — top commands executed by attackers
    geo_countries.py             — geographic distribution of attacks
    timeline.py                  — attack timeline and hourly distribution
    session_analysis.py          — session depth, command sequences, attacker profiles
    download_analysis.py         — downloaded files, architecture detection, IOC extraction

dionaea/
    stats_basic.py               — connections, unique IPs, connection types, protocols
    stats_by_event_type.py       — per-protocol event counts and top attacker IPs
    geo_countries.py             — attacker country distribution
    ip_top_attackers.py          — top IPs ranked by combined event volume
    ip_persistence.py            — IPs returning across multiple days
    malware_stats.py             — downloaded payload stats by MD5 and source domain
    malware_hashes.py            — unique vs duplicate payload hashes
    malware_urls.py              — download/offer URLs, normalized and ranked
    payload_timeline.py          — payload downloads by day and hour
    exploit_stats.py             — connections by protocol, transport, type
    timeline_hourly.py           — accepted connections by hour
    timeline_by_protocol_full.py — hourly activity broken down per protocol
    ip_service_correlation.py    — IPs hitting more than one service
    asn_analysis.py              — attacking IPs grouped by ASN
    infrastructure_analysis.py   — ASN/protocol matrix, portscan patterns, first/last seen
    hunter_1.py                  — binary sample analysis, IOC/family classification
    hunter_2.py                  — family grouping, intra-family Jaccard clustering, similarity graph generation
    reports/
        wannacry_2026.md         — cluster analysis of 269 WannaCry samples captured live

opencanary/
    stats_basic.py               — total events, logtype distribution, daily counts
    top_ips.py                   — top attacking IPs by event count
    top_usernames.py             — top USERNAME values across services
    geo_countries.py             — country/continent distribution by event volume
    extract_unique_ips.py        — dedup IP list for downstream GeoIP/ASN lookups
    geo_providers.py             — attacker distribution by ASN/org
    events_per_day.py            — daily event counts
    analyze_subnets.py           — top /24 and /16 attacker subnets
    attacks_per_service.py       — event counts by emulated service (RDP, VNC, Redis, NTP)
    rdp_logdata.py               — RDP-specific username/credential field analysis
    time_patterns.py             — hourly/weekday attack distribution, per-service peaks
    ip_persistence.py            — event volume and active-period distribution per IP
    ip_service_correlation.py    — IPs attacking multiple emulated services

telnethoney/
    telnet.py                     — the honeypot itself (custom BusyBox router emulation)
    top_ips.py                    — top source IPs by event count
    top_countries.py              — top countries by event count
    top_asn.py                    — top autonomous systems by event count
    hosting_vs_residential.py     — IP classification (hosting/VPN, residential, Tor)
    telnet_credentials.py         — top usernames, passwords, credential pairs
    telnet_commands.py            — top commands by frequency
    telnet_attacker_profiles.py   — behavioural classification (downloader, loader, etc.)
    telnet_sessions.py            — full command sequences per IP
    telnet_commands_by_hour.py    — command activity timeline
    delivery_methods.py           — payload delivery technique detection (wget, tftp, etc.)
    telnet_binary_handshake.py    — non-text/binary connection attempts
    architectures.py              — target CPU architectures referenced in commands

suricata/
    load_suricata.py              — base loader for eve.json, fast.log, stats.log
    suricata_alerts.py            — alert analysis (SIDs, signatures, frequency, top IPs)
    suricata_flow.py              — network flow analysis (flow_id, duration, bytes)
    suricata_http.py              — HTTP analysis (methods, URIs, User-Agent, downloads)
    suricata_dns.py               — DNS analysis (queries, record types, rare domains)
    suricata_tls.py               — TLS/JA3 analysis (JA3/JA3S fingerprints, certs, SNI)
    suricata_fileinfo.py          — file analysis (hashes, MIME types, extracted objects)
    suricata_smb.py               — SMB analysis (commands, anomalies, EternalBlue indicators)
    suricata_timeline.py          — event timeline (flow_id correlation, attack chains)
    sample_logs/
        eve_sample.json
        suricata_analysis.json
        README.md
    reports/
        suricata-findings.md
```

---

## Cowrie — corporate honeyfs

The default Cowrie filesystem looks like a generic Debian install — experienced attackers recognise it immediately. [install_dynamic_fs.sh](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/install_dynamic_fs.sh) replaces it with a simulated corporate cluster including:

- Kubernetes, Docker, Ansible, Terraform, Jenkins, GitLab Runner
- PostgreSQL, MySQL, Redis, RabbitMQ, Kafka, Zookeeper
- Prometheus, Grafana, Elasticsearch, Logstash, Kibana
- HashiCorp Vault, Consul, Nomad, Harbor registry, MinIO
- Fake credentials, SSH keys, database dumps, and CI/CD artefacts

Every run generates randomised usernames, passwords, GitHub tokens, and attacker IPs — so the environment looks different to each session.

**Log path** used by all scripts:
```
LOG_DIR = '/home/cowrie/cowrie/var/log/cowrie'
```
If your installation uses a different path, edit this constant at the top of each script.

---

## Script dependencies

Most scripts are standalone. Two exceptions:

**[`log_loader.py`](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/log_loader.py)** is used as a shared module by [`session_analysis.py`](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/session_analysis.py), [`attacker_profiling.py`](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/attacker_profiling.py), and [`classify_cowrie.py`](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/classify_cowrie.py). Keep it in the same directory.

**[analyze_chains.py](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/analyze_chains.py)** requires three input files generated by other scripts first:

- malware_commands.json ← from [analyze_creds_commands.py](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/analyze_creds_commands.py)
- malware_files.json    ← from [extract_downloads.py](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/extract_downloads.py)
- malware_uploads.json  ← from [analyze_uploads.py](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/analyze_uploads.py)


---

## Sample output

**analyze_cowrie.py** — 10-day overview
```
==================================================
 COWRIE 10-DAY REPORT
==================================================
Unique sessions : 52,278
Unique IPs      : 1,585

Top 10 IPs:
  45.148.10.183        19,586
  94.154.35.215        16,346
  45.148.10.240        16,145
  2.57.122.177         14,430
  185.246.128.133      12,196

Top passwords (successful logins):
  toor                  2,683
  3245gs5662d34         2,512
  admin                   171
  firedancer              165

Top commands:
   3499  uname -s -v -n -r -m
   2587  cd ~; chattr -ia .ssh; lockr -ia .ssh
   2587  cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...
```

**classify_cowrie.py** — session classifier (HASSH + regex + ML)
```
[+] Sessions loaded: 1,854
[+] Classified: 1,854 sessions

family
Cluster-0     1,349   (unclassified, ML-grouped)
Go-scanner      253   (SSH-2.0-Go crypto-targeting scanner)
Cluster-1       151
mdrfckr          77   (libssh_0.11.1 SSH backdoor)
Gafgyt           19   (DDoS bot loader)
```

**attack_stats.py** — full statistics with ASCII bar charts
```
============================================================
 COWRIE HONEYPOT — FULL STATISTICS REPORT
============================================================
  Connections      :  1,854
  Unique sessions  :  1,857
  Unique IPs       :    100
  Login failures   :  1,478
  Login successes  :    432
  Commands logged  :    335
  Payload downloads:     77

=== HASSH Fingerprints (top 5) ===
  0a07365c   709  Unknown
  f555226d   494  Unknown
  16443846   253  Go-scanner / SSH-2.0-Go
  a7a87fbe    19  Gafgyt loader

=== Session Duration Distribution ===
  <1s      ███████                                  266
  1-5s     ████████████████████████████████████████ 1,354
  5-30s    █████                                    192
  30s-2m                                             26
  >2m                                                19
```

**timeline_builder.py** — forensic session timeline
```
SESSION b890da0fdc04
IP      103.14.33.174
EVENTS  13

  +    0ms (+    0ms) [CONNECT ]
  +    1ms (+    1ms) [VERSION ] SSH-2.0-libssh_0.9.6
  +  216ms (+  215ms) [HASSH   ] hassh=f555226df1963d1d
  + 1116ms (+  899ms) [SUCCESS ] root:Welcome12!
  + 1560ms (+    1ms) [CMD     ] cd ~; chattr -ia .ssh; lockr -ia .ssh
  + 2263ms (+  228ms) [CMD     ] cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa...
  + 2482ms (+  218ms) [DOWNLOAD] sha=a8460f446be5...
  + 6597ms (+ 4113ms) [CLOSE   ] duration=6.6s
```

---

## Requirements

```
pip install pandas matplotlib scikit-learn
```

[analyze_payloads.py](https://github.com/dblanko/honeypot-analysis/blob/main/cowrie/analyze_payloads.py) also uses system tools: `file`, `strings`, `readelf`, `upx` (available on most Linux systems, install via:)
```
apt install binutils upx-ucl
```
---

## Dionaea — malware capture and clustering

Dionaea logs to a SQLite database (`dionaea.sqlite`); the analysis scripts query `connections`, `downloads`, `offers`, `mysql_commands`, `mssql_commands`, `dcerpcrequests`, `dcerpcbinds`, and `logins` directly. Most scripts accept `--last-week`, `--last-month`, or `--from`/`--to` date ranges.

**Path constant** in all scripts:
```
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
```

[infrastructure_analysis.py](https://github.com/dblanko/honeypot-analysis/blob/main/dionaea/infrastructure_analysis.py) and 
[asn_analysis.py](https://github.com/dblanko/honeypot-analysis/blob/main/dionaea/asn_analysis.py) 
additionally require a local GeoLite2-ASN database; both autodetect common install paths or accept --geo-asn.

[hunter_v1.py](https://github.com/dblanko/honeypot-analysis/blob/main/dionaea/hunter_1.py) performs fast static analysis of captured binaries (first 256 KB only): 
extracts strings, computes entropy and PE timestamps, matches IOC patterns, classifies samples into families 
(WannaCry, Cryptominer, LinuxBot, Loader, RAT, Unknown), produces Top‑N lists, and writes both JSON and Markdown reports. 
Designed for large collections (tens of thousands of files).

[hunter_v2.py](https://github.com/dblanko/honeypot-analysis/blob/main/dionaea/hunter_v2.py) groups analysed samples by family (WannaCry, Loader, LinuxBot, Unknown) 
and performs intra‑family clustering using Jaccard similarity of extracted strings. 
Outputs a JSON graph (nodes + edges) and a Markdown cluster report.

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

See [`dionaea/reports/wannacry_2026.md`](dionaea/reports/wannacry_2026.md) for the full cluster writeup: 269 distinct WannaCry samples captured live, all clustering into a single connected component.

---

## OpenCanary — multi-service emulation

OpenCanary writes a single JSON-lines log (`opencanary.log`); scripts work against a time-sliced extract (`period.json`) produced with a simple `awk` range filter. Each script reads the file once and aggregates by `logtype`, `src_host`, or fields inside `logdata`.

**Path constant** in all scripts:
```
LOGFILE = "period.json"
```

[geo_countries.py](https://github.com/dblanko/honeypot-analysis/blob/main/opencanary/geo_countries.py) and [geo_providers.py](https://github.com/dblanko/honeypot-analysis/blob/main/opencanary/geo_providers.py) require local GeoLite2-Country and GeoLite2-ASN databases.

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

---

## Telnethoney — custom IoT/Telnet honeypot

Telnethoney [telnet.py](https://github.com/dblanko/honeypot-analysis/blob/main/telnethoney/telnet.py) is a self-written honeypot, not a third-party project. It emulates a BusyBox-based IoT router: fake `ps`, `top`, `df`, `ifconfig`, `uname`, `/proc/cpuinfo`, working `echo >`/`echo >>` file redirection, and a minimal HTTP server that serves fake binaries to scripted downloaders. Every login attempt, command, and HTTP request is logged to a single JSON-lines file, enriched at write time with GeoIP/ASN lookups and an IP classification (hosting/VPN, residential, Tor, unknown).

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
Downloader: 295
Malware Execution: 12
```

**delivery_methods.py**
```
=== Delivery Methods ===
wget: 236
curl: 124
busybox wget: 93
nc: 72
tftp: 48
base64: 33
bash tcp: 16
busybox curl: 11
toybox nc: 11
socat: 11
```

**architectures.py**
```
=== Architectures Targeted ===
mips: 73
mpsl: 72
x86: 64
```
---


## Suricata — network-level IDS

Suricata runs alongside all four honeypots, capturing every packet at the network layer.
Where honeypots see application-layer interactions (credentials, commands, payloads),
Suricata sees the complete network picture: flows, protocol fingerprints, and signature matches.

One day of eve.json output: **220,513 events** — 67,631 flows, 50,287 alerts, 39,577 RDP events, 39,468 SMB events.

| Script | Purpose |
|--------|---------|
| `load_suricata.py` | Core log loader — shared module used by all other scripts |
| `suricata_alerts.py` | Alert analysis: top signatures, categories, per-IP summary |
| `suricata_flow.py` | Flow analysis: protocols, ports, traffic volume |
| `suricata_smb.py` | SMB analysis: EternalBlue probes, SMB1 negotiation |
| `suricata_http.py` | HTTP scanner behaviour: user-agents, URIs, file extensions |
| `suricata_dns.py` | DNS query analysis: DGA detection, top domains |
| `suricata_tls.py` | TLS/JA3 fingerprinting |
| `suricata_fileinfo.py` | File transfer analysis |
| `suricata_timeline.py` | Forensic event timeline |

**Log path** used by all scripts:
EVE_LOG = '/var/log/suricata/eve.json'

## Sample output

**suricata_alerts.py** suricata alert analysis module
```
=== Top Signatures (SID) ===
SID 2001330: 40492 alerts
SID 2402000: 1212 alerts
SID 2012709: 858 alerts
SID 2022082: 784 alerts
SID 2038967: 753 alerts


=== Top Signature Names ===
ET INFO RDP - Response To External Host: 40492 alerts
ET DROP Dshield Block Listed Source group 1: 1212 alerts
ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request: 858 alerts
ET INFO External IP Lookup ip-api.com: 784 alerts
ET INFO SSH-2.0-Go version string Observed in Network Traffic: 753 alerts
GPL NETBIOS SMB-DS IPC$ unicode share access: 534 alerts
```

**suricata_http.py** suricata HTTP analysis module
```
=== HTTP Methods === 
GET: 3410 
POST: 53 
OPTIONS: 6 
CONNECT: 3 
MGLNDD_65.108.249.205_9080:1 
MGLNDD_65.108.249.205_3000:1 

=== Top URIs === 
/: 381 
/json/223.123.38.120?fields=status,country,city,isp,org,as,proxy,hosting: 78 
/json/123.13.116.196?fields=status,country,city,isp,org,as,proxy,hosting: 76 
/json/72.255.59.86?fields=status,country,city,isp,org,as,proxy,hosting: 75 
/json/223.123.38.127?fields=status,country,city,isp,org,as,proxy,hosting: 75 
/json/175.107.233.125?fields=status,country,city,isp,org,as,proxy,hosting: 75 
```

**suricata_dns.py** — suricata DNS analysis module
```
=== NXDOMAIN === 
version.bind: 7 
: 2 
www.wikipedia.org: 2 
VERSION.BIND: 2 
hostname.bind: 2 
id.server: 2 

=== Rare TLDs === 
.bind: 25 
.BIND: 4 
.server: 4
```

**suricata_smb.py** — behavioral SMB analysis for Suricata
```
=== SMB Scanners (high-frequency NEGOTIATE/SESSION_SETUP) === 
181.174.229.52: 6426 
223.100.68.193: 5198 
189.151.28.7: 4463 
41.226.181.214: 4063 
115.91.19.219: 3745 

=== SMB Brute-force Candidates (repeated SESSION_SETUP/LOGOFF) === 
181.174.229.52: 3212 
223.100.68.193: 2598 
189.151.28.7: 2231 
41.226.181.214: 2031 
115.91.19.219: 1870 
```

---

**Cross-sensor value:** Suricata's EternalBlue signature (`ET EXPLOIT Possible ETERNALBLUE Probe MS17-010`)
fired on the same SMB sessions that delivered 269 WannaCry payloads to Dionaea —
providing network-level confirmation of what the malware honeypot captured at the application layer.

Full methodology: [Book 5 — Suricata: Network Guardian](https://leanpub.com/suricata) ·
[Book 6 — Correlation](https://leanpub.com/correlation)


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


