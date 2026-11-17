# honeypot-analysis

Analysis scripts for Cowrie, OpenCanary, Dionaea, Telnethoney and Suricata.
Part of the [SSHLab Security Research Series](https://sshlab.eu): six books on honeypot deployment and log analysis using real attack data from a live VPS.

All scripts run against real data collected from this deployment. No synthetic datasets, no lab environments.

## Sensors

One VPS runs five sensors simultaneously:

| Sensor | What it does | Folder |
|--------|--------------|--------|
| Cowrie | SSH/Telnet honeypot: credential harvesting, session logging | [`cowrie/`](cowrie/) |
| OpenCanary | Multi-service honeypot: RDP, MSSQL, HTTP, SMB, MySQL | [`opencanary/`](opencanary/) |
| Dionaea | Malware honeypot: full binary capture via SMB, MySQL, MSSQL | [`dionaea/`](dionaea/) |
| Telnethoney | Custom IoT/Telnet honeypot (self-written, emulates a BusyBox router) | [`telnethoney/`](telnethoney/) |
| Suricata | Network IDS: cross-sensor correlation | [`suricata/`](suricata/) |

Each folder has its own README with the script list, log paths, dependencies and sample output.
Cross-sensor material is in [`correlation/`](correlation/).

## Quick start

```
pip install -r requirements.txt
```

Every script reads its log from a path constant at the top of the file (for example `LOG_DIR`, `DB_PATH`, `LOGFILE`, `EVE_LOG`). Edit it if your installation differs; defaults are listed in each folder's README.

## Findings

| Report | Sensor | Summary |
|--------|--------|---------|
| [WannaCry cluster 2026](dionaea/reports/wannacry_2026.md) | Dionaea | 269 samples, one cluster, May 2017 binary still active |
| [Cowrie findings](cowrie/reports/cowrie-findings.md) | Cowrie | 52,278 sessions, SSH key injection dominant pattern |
| [OpenCanary findings](opencanary/reports/opencanary-findings.md) | OpenCanary | 544,908 events, Redis wordlist reconstruction, RDP cluster |
| [Telnethoney findings](telnethoney/reports/telnethoney-findings.md) | Telnethoney | 260,544 events, hex-encoded auth_ok dominant command |
| [Suricata findings](suricata/reports/suricata-findings.md) | Suricata | 220,513 events/day, EternalBlue + WannaCry cross-sensor |
| [Correlation sample](correlation/reports/daily_2026-04-11_anon.md) | All sensors | Daily cross-sensor report, 18 correlated IPs |

## Books

These scripts are the maintained, tested versions of the tools documented in the series. Minor differences from the print appendices reflect path corrections and enhancements made after publication.

| Book | Sensor | Scripts |
|------|--------|---------|
| [Book 1 — Cowrie SSH Honeypot](https://leanpub.com/cowrie) | Cowrie | [`cowrie/`](cowrie/) |
| [Book 2 — OpenCanary](https://leanpub.com/opencanary-honeypot) | OpenCanary | [`opencanary/`](opencanary/) |
| [Book 3 — Dionaea Malware Honeypot](https://leanpub.com/dionaeahoneypot) | Dionaea | [`dionaea/`](dionaea/) |
| [Book 4 — Telnethoney IoT](https://leanpub.com/telnethoney) | Telnethoney | [`telnethoney/`](telnethoney/) |
| [Book 5 — Suricata](https://leanpub.com/suricata) | Suricata | [`suricata/`](suricata/) |
| [Book 6 — Correlation](https://leanpub.com/correlation) | All sensors | [`correlation/`](correlation/) |

Full series: [Security Research Series](https://leanpub.com/b/securityresearchseries)

## License

MIT, see [LICENSE](LICENSE).

Descriptive text in the READMEs was drafted with the help of an AI writing assistant, since English is not the author's first language. All scripts, data, findings and technical content are the author's own work.
