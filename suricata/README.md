# Suricata

Suricata runs alongside the four honeypots and captures every packet at the network layer. Where honeypots see application-layer interactions (credentials, commands, payloads), Suricata sees the complete network picture: flows, protocol fingerprints and signature matches.

One day of eve.json output: **220,513 events**: 67,631 flows, 50,287 alerts, 39,577 RDP events, 39,468 SMB events.

Findings: [reports/suricata-findings.md](reports/suricata-findings.md) · Sample data: [sample_logs/](sample_logs/)

## Log path

```
EVE_LOG = '/var/log/suricata/eve.json'
```

## Scripts

| Script | Purpose |
|--------|---------|
| `load_suricata.py` | Base loader for eve.json, fast.log, stats.log |
| `suricata_alerts.py` | Alert analysis: SIDs, signatures, frequency, top IPs |
| `suricata_flow.py` | Network flows: flow_id, duration, bytes |
| `suricata_http.py` | HTTP: methods, URIs, User-Agent, downloads |
| `suricata_dns.py` | DNS: queries, record types, rare domains |
| `suricata_tls.py` | TLS/JA3: fingerprints, certificates, SNI |
| `suricata_fileinfo.py` | Files: hashes, MIME types, extracted objects |
| `suricata_smb.py` | SMB: commands, anomalies, EternalBlue indicators |
| `suricata_timeline.py` | Event timeline: flow_id correlation, attack chains |

## Cross-sensor value

Suricata's EternalBlue signature (`ET EXPLOIT Possible ETERNALBLUE Probe MS17-010`) fired on the same SMB sessions that delivered 269 WannaCry payloads to Dionaea, giving network-level confirmation of what the malware honeypot captured at the application layer.

Full methodology: [Book 5 — Suricata: Network Guardian](https://leanpub.com/suricata) · [Book 6 — Correlation](https://leanpub.com/correlation)

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
