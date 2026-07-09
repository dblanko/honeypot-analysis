# Cowrie Sample Log

Anonymised extract from a live Cowrie SSH honeypot deployment.
72 events across 4 sessions showing different attacker behaviours.

## Sessions included

| Session | Pattern | Events |
|---------|---------|--------|
| 0a9d2fa29c92 | Login success + commands + file download | 16 |
| 102a22456107 | Login success + 9 commands (active session) | 34 |
| 6a8140876968 | Brute-force, no success | 5 |
| 89e1d818434a | Login success + TCP tunnel (pivot attempt) | 17 |

## Anonymisation

- Source IPs replaced with 203.0.113.x (RFC 5737 documentation range)
- Honeypot IP replaced with 192.0.2.1
- Sensor name replaced with `honeypot-vps`
- UUIDs removed

## Usage

Run any script from the [`cowrie/`](https://github.com/dblanko/honeypot-analysis/tree/main/cowrie) directory against this file:

```bash
python3 analyze_cowrie.py cowrie/sample_logs/cowrie_sample.json
python3 attack_stats.py cowrie/sample_logs/cowrie_sample.json
python3 timeline_builder.py --session 102a22456107 \
  --log cowrie/sample_logs/cowrie_sample.json
```
