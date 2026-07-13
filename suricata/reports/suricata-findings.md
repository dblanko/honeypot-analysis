# What Suricata Sees — Network-Level View of a Honeypot Lab

While Cowrie, Dionaea, OpenCanary, and Telnethoney capture application-layer interactions, Suricata operates at the network level — seeing every packet, every connection, every protocol. Running on the same VPS as the other sensors, it provides the complete picture that no single honeypot can.

**The event distribution**

One day of Suricata eve.json output:

| Event type | Count |
|------------|-------|
| flow | 67,631 |
| alert | 50,287 |
| rdp | 39,577 |
| smb | 39,468 |
| stats | 8,283 |
| ssh | 4,836 |
| http | 3,498 |
| fileinfo | 3,039 |
| dns | 2,371 |
| tls | 673 |
| anomaly | 500 |
| rfb | 227 |

RDP and SMB — the two services OpenCanary exposes — dominate at the network layer. 67,631 flows and 50,287 alerts in a single day from a single VPS with no production services.

**The top alerts**

| Signature | Alerts |
|-----------|--------|
| ET INFO RDP - Response To External Host | 40,492 |
| ET DROP Dshield Block Listed Source group 1 | 1,212 |
| ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request | 858 |
| ET INFO External IP Lookup ip-api.com | 784 |
| ET INFO SSH-2.0-Go version string Observed | 753 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 534 |

The top signature — `ET INFO RDP - Response To External Host` — fired 40,492 times. This is not a malicious alert; it is informational, triggered every time the RDP honeypot responds to an inbound connection. It maps directly to OpenCanary's RDP traffic volume.

More significant: `ET EXPLOIT Possible ETERNALBLUE Probe MS17-010` appeared with two variants (`MSF style` and `Generic Flags`) — the same SMB traffic that was delivering WannaCry payloads to Dionaea on the same server, now visible at the network level with Suricata signatures firing in real time.

**SID → flow correlation**

SID 2001330 (RDP response): 19,756 correlated flows — nearly half of all flows.
SID 2402000 (Dshield blocklist): 1,210 correlated flows.

Flow correlation links network-level alerts to the actual TCP sessions, providing duration, byte counts, and connection state for each alert — something no honeypot log alone can supply.

**The flow picture**

Protocol breakdown across 67,631 flows:

| Protocol | Flows |
|----------|-------|
| TCP | 64,716 (95.7%) |
| UDP | 1,854 |
| ICMP | 920 |
| IPv6-ICMP | 140 |

Top destination ports:
- 3389 (RDP): 20,051 flows
- 445 (SMB): 19,695 flows
- 22 (SSH): 3,848 flows
- 80 (HTTP): 2,966 flows
- 53 (DNS): 1,266 flows
- 23 (Telnet): 423 flows

Traffic volume: 720 MB sent to server, 4.5 GB received from server — the asymmetry reflects RDP session establishment overhead from inbound scanning.

**SMB: EternalBlue at the network layer**

19,331 `SMB1_COMMAND_NEGOTIATE_PROTOCOL` events in one day. Top SMB scanners:

| IP | SMB events |
|----|-----------|
| 181.174.229.52 | 6,426 |
| 223.100.68.193 | 5,198 |
| 189.151.28.7 | 4,463 |
| 41.226.181.214 | 4,063 |
| 115.91.19.219 | 3,745 |

These are the same sources triggering EternalBlue signatures. Suricata fires `ET EXPLOIT Possible ETERNALBLUE Probe MS17-010` on their SMB sessions — the same exploitation pattern that delivered 269 WannaCry payloads to Dionaea.

**HTTP: what scanners are looking for**

3,498 HTTP events. Top user-agents:
- `python-requests/2.31.0`: 784 — automated scanner
- Generic Mozilla strings (Chrome/Firefox spoofed): ~1,400

Top URIs probed: `/`, then dozens of variations of `/json/<ip>?fields=status,country,city,isp,org,as,proxy,hosting` — ip-api.com geolocation queries. The scanners are looking up IP reputations, including the honeypot's own IP (784 queries to `ip-api.com`).

File extensions in HTTP fileinfo events:
`.php` (473), `.json` (154), `.js` (151), `.txt` (124), `.yml` (122), `.bak` (113), `.yaml` (112), `.conf` (111), `.old` (111), `.env` (111)

Config files, backup files, environment files. Automated vulnerability scanners looking for exposed credentials and misconfigurations.

**DNS: what the server resolves**

2,371 DNS events. Top query: `ip-api.com` — 1,796 times. This is outbound from the honeypot's network neighborhood: attackers looking up IP reputation data before deciding what to do next.

`version.bind` appeared 21 times with NXDOMAIN — DNS version probing (attempts to fingerprint the DNS server software). 27 DGA-like domains flagged by heuristic, all false positives: `_https._tcp.packages.grafana.com`, `_https._tcp.mirror.hetzner.com` — legitimate hostnames that trigger consonant-ratio heuristics.

**The cross-sensor view**

Suricata's value is not in what it catches independently — it is in what it adds to the other sensors. An EternalBlue probe that Dionaea logs as a connection and a binary capture becomes, with Suricata, a complete picture: the SMB negotiation sequence, the exploit signature firing, the flow duration, the byte count. A WannaCry delivery that Dionaea records as a file download becomes, with Suricata, a correlated network event with timing, source, and protocol-level detail.

This is the methodology documented in Book 6 (Correlation): no single sensor tells the full story. The network layer and the application layer together do.

Analysis scripts for Suricata eve.json:
[github.com/dblanko/honeypot-analysis](https://github.com/dblanko/honeypot-analysis)
