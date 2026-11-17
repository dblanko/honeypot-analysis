# Telnethoney

[`telnet.py`](telnet.py) is a self-written honeypot, not a third-party project. It emulates a BusyBox-based IoT router: fake `ps`, `top`, `df`, `ifconfig`, `uname` and `/proc/cpuinfo`, working `echo >` / `echo >>` file redirection, and a minimal HTTP server that serves fake binaries to scripted downloaders.

Every login attempt, command and HTTP request is logged to a single JSON-lines file, enriched at write time with GeoIP/ASN lookups and an IP classification (hosting/VPN, residential, Tor, unknown).

Findings: [reports/telnethoney-findings.md](reports/telnethoney-findings.md) · Sample data: [sample_logs/](sample_logs/)

## Log path

All analysis scripts use:

```
LOGFILE = 'telnethoney.json'
```

## Scripts

| Script | Purpose |
|--------|---------|
| `telnet.py` | The honeypot itself |
| `top_ips.py` | Top source IPs by event count |
| `top_countries.py` | Top countries by event count |
| `top_asn.py` | Top autonomous systems by event count |
| `hosting_vs_residential.py` | IP classification (hosting/VPN, residential, Tor) |
| `telnet_credentials.py` | Top usernames, passwords, credential pairs |
| `telnet_commands.py` | Top commands by frequency |
| `telnet_commands_by_hour.py` | Command activity timeline |
| `telnet_attacker_profiles.py` | Behavioural classification (downloader, loader, etc.) |
| `telnet_sessions.py` | Full command sequences per IP |
| `delivery_methods.py` | Payload delivery technique detection (wget, tftp, etc.) |
| `telnet_binary_handshake.py` | Non-text/binary connection attempts |
| `architectures.py` | Target CPU architectures referenced in commands |

## Sample output

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
