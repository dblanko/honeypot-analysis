# What 52,000 SSH Sessions Look Like — Cowrie Honeypot Data

A Cowrie SSH honeypot running on a single public VPS collected 52,278 sessions from 1,585 unique IP addresses. This is what the data shows.

**The credentials**

The most common successful login password was `3245gs5662d34` — 2,683 successful authentications. Second was `toor` (2,512). These are not generic weak passwords. They are specific to SSH brute-force toolkits targeting Linux servers, and their prevalence indicates a coordinated credential-stuffing operation running the same wordlist across millions of targets simultaneously.

`root` accounted for 13,480 successful logins by username. No other username came close. The attack surface for SSH in 2026 remains almost entirely concentrated on the root account.

**The commands**

The most executed command — 3,499 times — was `uname -s -v -n -r -m`. System fingerprinting, run before anything else. The second and third most common were identical variations of:

```
cd ~; chattr -ia .ssh; lockr -ia .ssh
```

This is SSH key injection: remove immutable flags from `.ssh/`, wipe authorized keys, replace with the attacker's own key. 2,587 sessions attempted this sequence. It is the dominant post-login action in this dataset — not data exfiltration, not cryptomining setup, not ransomware. Key injection for persistent access.

**The fingerprints**

HASSH analysis identified the top client fingerprints:

- `16443846` — Go-scanner / SSH-2.0-Go (253 sessions): crypto-targeting scanner written in Go
- `a7a87fbe` — Gafgyt loader (19 sessions): DDoS botnet
- `03a80b21` — mdrfckr / libssh_0.11.1 (77 sessions): SSH backdoor

The mdrfckr family is particularly consistent: HASSH fingerprint, `chattr -ia .ssh` command sequence, and SSH key injection in a single session. All three markers together identify the same tool across 77 sessions from different source IPs.

**The payloads**

29 unique payload SHA256 hashes were captured via file download events. Architecture distribution across the samples: x86_64, ARM, ARM64, MIPS — a cross-platform delivery toolkit. One campaign (SHA256: `45bff40a...`) delivered the same binary from three different source IPs, confirming coordinated infrastructure rather than independent actors.

**The timeline**

Peak attack hour: 05:00 UTC. This is consistent across the full dataset. The pattern — concentrated early morning UTC activity, not spread evenly across 24 hours — indicates infrastructure operating from a specific timezone, not a globally distributed botnet.

**What this means**

52,278 sessions. 1,585 unique IPs. The session duration distribution is the most telling detail: 73% of sessions lasted between 1 and 5 seconds. These are not human operators. They are automated tools running credential lists, fingerprinting the system, and moving on — processing thousands of targets per hour from the same infrastructure.

The RedTail operator was the exception: an SFTP session uploading `redtail.arm8`, `redtail.i686`, `redtail.x86_64`, and `setup.sh` — 97 commands across the session. One human operator, identifiable by behaviour, among tens of thousands of automated connections.
