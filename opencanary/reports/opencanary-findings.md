# 544,908 Events in 20 Days — OpenCanary Multi-Service Honeypot Data

An OpenCanary honeypot exposing RDP, Redis, VNC, SNMP, NTP, and Git on a single public VPS collected 544,908 events from 1,556 unique IP addresses over 20 days. The first connection arrived 2 minutes and 15 seconds after deployment.

**The service distribution**

| Service | Events | Share |
|---------|--------|-------|
| RDP (3389) | 485,752 | 89.1% |
| Redis (6379) | 55,634 | 10.2% |
| NTP (123) | 805 | 0.1% |
| SNMP (161) | 217 | <0.1% |
| VNC (5000) | 60 | <0.1% |
| Git (9418) | 4 | <0.01% |

RDP dominates to the point where all other services are statistical noise in terms of volume. But volume and analytical value are not the same thing.

**RDP: the fingerprint dataset**

485,752 RDP events. No passwords — RDP NLA/CredSSP encrypts credentials before they reach the honeypot. What is visible: 50.8% of events contain no username at all (pure port scanning, not login attempts), and 46.4% contain a real username string.

Top usernames across 225,557 brute-force attempts:

| Username | Events | Notes |
|----------|--------|-------|
| test | 135,366 | First entry in most RDP wordlists |
| hello | 33,268 | FreeRDP-based tool fingerprint |
| 45 | 29,024 | First octets of the honeypot's IP address |
| Administr | 23,657 | Truncation artifact — field length limit in scanner |

`hello` is analytically more useful than `test`. It is specific to FreeRDP-based scanning tools and Asian-origin botnet families. `45` — the first two digits of the honeypot IP — means the scanner derives login candidates from the target IP address itself. That is a distinct class of tool, not a generic credential list.

**The 185.156.73.x cluster**

Six IP addresses from the 185.156.73.0/24 range generated 196,000+ events — 40% of all RDP traffic. Their behaviour is coordinated: all six active simultaneously from March 2–7, peak at 19:00 UTC every Sunday, two primary nodes (.169 and .74) active from day one for seven full days. Events from different nodes in the cluster interleave with millisecond precision — the fingerprint of centralised scheduling or a C2 system.

185.156.73.169 alone: 62,399 events. 185.218.138.3 generated 45,194 events in under one hour on day one — saturation scanning, single pass, no return.

Blocking the /24 eliminates 40% of RDP traffic with one firewall rule.

**Redis: the wordlist reconstruction**

55,634 Redis events. 89% from a single IP: 87.120.166.19 (Neterra Ltd, Bulgaria). This IP ran for approximately 11 hours across two days and never returned.

Every password in the wordlist appears exactly 748 times. 49,513 events ÷ 748 = 66.2 passwords in the list. The fractional result means the 67th cycle was interrupted — consistent with a time-limited run. Perfect uniformity rules out distributed infrastructure; this was a single process, single wordlist, single run.

The wordlist itself identifies the tool: `foobared` (the example password from Redis documentation), `redis` (service name as password), `Password123`, `test123`. A generic credential tool does not include `foobared`. This was built specifically for Redis.

Peak Redis activity: 05:00 UTC — completely independent of the RDP peak at 19:00 UTC. Two separate operators, two separate timezones, converging on the same server without coordination.

**VNC: 59 connections in 2.5 seconds**

60 VNC events, 2 source IPs. 89.185.27.123 opened approximately 10 simultaneous connections and ran its wordlist in 2.5 seconds — from 19:32:40.592 to 19:32:43.095 UTC. OpenCanary's dictionary matching recovered 7 passwords from the challenge/response pairs: `administrator`, `password`, `123456`, `root`, `1234`. 53 events matched none — the attacker's wordlist contained non-standard entries not in OpenCanary's dictionary.

This is the only event in the entire 20-day dataset that resembles what most people imagine a "hacking attempt" looks like: a targeted, specialised tool, processing a wordlist, completing in seconds. Everything else is background infrastructure.

**NTP and SNMP: reconnaissance, not attacks**

805 NTP events, every single one a `monlist` request — the amplification DDoS probe. The scanner is building a list of NTP servers that respond to monlist, to use as amplification nodes in future DDoS attacks. Our honeypot appeared to be one of them. 164.90.186.125 sent 333 of these probes — 42% of all NTP traffic.

217 SNMP events from 130 unique IPs, all using community string `public`. OID requests targeting `sysDescr` and `sysName` — OS version, kernel, hostname. Not exploitation. Cataloguing. The data goes into a database of interesting targets for later use.

**Geography: the infrastructure paradox**

Ukraine accounts for 50.4% of events — from 19 unique IP addresses. The United States accounts for 13% — from 645 unique IP addresses. Ukraine's dominance reflects the 185.156.73.x cluster concentration, not Ukrainian actors. The US figure reflects distributed cloud provider infrastructure across hundreds of independent scanners.

Average events per Ukrainian IP: 14,388. Average events per US IP: 109. Same internet, different infrastructure models.

**The attacker taxonomy**

97% of attacking IPs targeted exactly one service. Only two IPs targeted three or more services — both belong to Censys, the internet-wide security research scanner.

Three distinct archetypes emerge:
- **Botnet cluster**: coordinated nodes, tens of thousands of events, consistent schedule, eliminable with a single /24 block
- **Specialist tool**: single IP, single service, time-limited wordlist run, analytically distinctive in retrospect
- **Background scanner**: one or two events per IP, no exploitation intent, feeds the target databases that the first two archetypes use

563 IPs appeared exactly once. 14 IPs generated more than 10,000 events each. The single highest-volume attacker (185.156.73.169, 62,399 events) generated more traffic than the combined total of 1,100+ low-volume IPs.

**The deployment note**

The first external event arrived at 15:15:57 UTC — 2 minutes and 15 seconds after OpenCanary started. By 18:00 UTC the same day, the server had logged tens of thousands of events. Peak hour across the entire 20-day period: 19:00 UTC on February 22.

This is not unusual. It is the standard operational environment for any internet-connected server with open ports in 2026.
