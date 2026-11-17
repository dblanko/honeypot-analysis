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
Cross-sensor material is in [`correlation/reports/`](correlation/reports/).

## Before you start

This repository contains **analysis scripts only** (plus the Telnethoney honeypot itself). The scripts expect logs from sensors that are already deployed and have been collecting data for a while. Installing and configuring the sensors is not covered here; see the books and the upstream documentation.

| Sensor | Install separately | What the scripts read |
|--------|--------------------|-----------------------|
| Cowrie | [cowrie/cowrie](https://github.com/cowrie/cowrie) | JSON logs in `LOG_DIR` |
| OpenCanary | [thinkst/opencanary](https://github.com/thinkst/opencanary) | `opencanary.log`, sliced into `period.json` |
| Dionaea | [DinoTools/dionaea](https://github.com/DinoTools/dionaea) | SQLite database (`DB_PATH`) |
| Telnethoney | nothing, [`telnet.py`](telnethoney/telnet.py) is in this repo | `telnethoney.json` |
| Suricata | [suricata.io](https://suricata.io) | `eve.json` |

Some scripts need extras beyond Python packages:

- GeoIP/ASN scripts in `dionaea/` and `opencanary/` need local [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases.
- `cowrie/analyze_payloads.py` uses system tools (`file`, `strings`, `readelf`, `upx`).

## Quick start

1. Deploy the sensors you want to analyse and let them collect data.
2. Install the Python dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Open the script you want to run and set its log path constant (`LOG_DIR`, `DB_PATH`, `LOGFILE` or `EVE_LOG`) to your own path. Defaults are listed in each folder's README.
4. Run it: `python3 <sensor>/<script>.py`

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
| [Book 6 — Correlation](https://leanpub.com/correlation) | All sensors | [`correlation/reports/`](correlation/reports/) |

Full series: [Security Research Series](https://leanpub.com/b/securityresearchseries)

## License

MIT, see [LICENSE](LICENSE).

Descriptive text in the READMEs was drafted with the help of an AI writing assistant, since English is not the author's first language. All scripts, data, findings and technical content are the author's own work.
