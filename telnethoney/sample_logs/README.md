# Telnethoney Sample Log

Anonymised extract from a live Telnethoney IoT/Telnet honeypot deployment.
60 events across 4 source IPs showing distinct attacker behaviour patterns.

## Sessions included

| IP | Country | Pattern | Events |
|-----|---------|---------|--------|
| 203.0.113.1 | Germany | Interactive session: login + ls, whoami, wget | 20 |
| 203.0.113.2 | Russia | IoT/router scanner: gpon, linuxshell, 7ujMko0admin | 20 |
| 203.0.113.3 | — | HTTP scanner, no credentials | 10 |
| 203.0.113.4 | Singapore | IoT botnet: hex-encoded auth_ok (\x61\x75\x74\x68...) | 10 |

## Anonymisation

- Source IPs replaced with 203.0.113.x (RFC 5737 documentation range)
- Geo data reduced to country only
- Timestamps preserved

## Usage

Run any script from the [`telnethoney/`](https://github.com/dblanko/honeypot-analysis/tree/main/telnethoney) directory against this file:

```bash
python3 top_ips.py
python3 telnet_credentials.py
python3 telnet_commands.py
```

Edit the `LOGFILE` constant at the top of each script to point to this file.
