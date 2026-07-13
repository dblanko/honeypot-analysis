# Suricata Sample Data

Anonymised extract from a live Suricata IDS deployment monitoring the full honeypot lab
(Cowrie · Dionaea · OpenCanary · Telnethoney) on a single VPS.

## Files

| File | Description |
|------|-------------|
| `eve_sample.json` | 36 anonymised eve.json events (flow, alert, smb, rdp, ssh, http, dns, tls) |
| `suricata_analysis_sample.json` | Sample output from `suricata_alerts.py` — per-IP alert summary |

## eve_sample.json — event types included

| Type | Count | Notes |
|------|-------|-------|
| flow | 8 | TCP/UDP session summaries |
| alert | 8 | Includes EternalBlue (MS17-010) and Dshield signatures |
| rdp | 4 | RDP session events |
| smb | 4 | SMB1 negotiate + session setup |
| ssh | 3 | SSH client version strings |
| http | 3 | Scanner HTTP requests |
| dns | 2 | DNS query events |
| tls | 2 | JA3/JA3S fingerprints |

## Anonymisation

- All external IPs replaced with 203.0.113.x (RFC 5737 documentation range)
- Honeypot IP replaced with 192.0.2.1
- Interface name removed

## Usage

Run any script from the [`suricata/`](https://github.com/dblanko/honeypot-analysis/tree/main/suricata) directory:

```bash
python3 load_suricata.py suricata/sample_logs/eve_sample.json
python3 suricata_alerts.py suricata/sample_logs/eve_sample.json
python3 suricata_smb.py suricata/sample_logs/eve_sample.json
python3 suricata_timeline.py suricata/sample_logs/eve_sample.json
```

[`load_suricata.py`](https://github.com/dblanko/honeypot-analysis/blob/main/suricata/load_suricata.py) is a shared module — keep it in the same directory as the other scripts.
