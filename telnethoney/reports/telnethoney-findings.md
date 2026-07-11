# 260,000 Telnet Connections in 72 Hours — IoT Honeypot Data

A custom-written Telnet/IoT honeypot — emulating a BusyBox router — collected 260,544 events from 8,437 unique IP addresses. The dominant traffic was not what most people expect.

**The dominant command**

The single most executed command, appearing 35,783 times:

```
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

Decoded: `auth_ok`. This is an IoT botnet authentication probe — a hex-encoded string sent to verify that a device accepted the login. The honeypot responded as a BusyBox router; the botnet confirmed authentication and logged the device as compromised. 35,783 times.

This command does not appear in any human operator session. It is the calling card of automated IoT malware — Mirai variants and derivatives — that authenticate, confirm, and move on without ever issuing a meaningful follow-up command to the honeypot.

**The geographic distribution**

Top countries by event volume:

| Country | Events |
|---------|--------|
| Singapore | 70,625 |
| Pakistan | 33,439 |
| United States | 24,875 |
| China | 20,252 |
| Brazil | 17,146 |

Singapore at the top reflects hosting infrastructure concentration, not Singaporean actors. The VPS providers in Singapore (DigitalOcean, Vultr, Linode) are standard infrastructure for IoT botnet operations — cheap, fast, and distant from the operators.

**Infrastructure classification**

| Class | Events |
|-------|--------|
| VPN or hosting | 128,592 |
| Residential or unknown | 104,551 |
| Unknown | 26,019 |
| Tor | 1,382 |

49% of all events came from identifiable VPS/hosting infrastructure. 40% from residential IPs — compromised home routers and IoT devices that are themselves part of botnets. 0.5% from Tor exit nodes.

**The credential distribution**

38,187 events included credentials. `root` appeared 26,139 times as the username — 68% of all credential events. The next entries: `admin` (1,007), `ubuntu` (697), `user` (479). The credential set is almost entirely IoT-default: these are the factory-set usernames on routers, cameras, and embedded devices, not human-chosen passwords.

One anomalous entry in the top usernames: a 169-character binary string containing `admin.$cmd` — a MongoDB injection attempt routed through a Telnet connection. Not a router scanner. Something else probing the port.

**The interactive operator**

One session from Germany (203.0.113.1 in the anonymised sample) was a human operator: `ls`, `whoami`, `wget http://example.com/test`, `exit`. Three credentials attempted first. Then manual exploration. This is the behavioural signature of a person, not a tool — distinguishable from the 260,000 automated connections by command diversity and timing.

**The router scanner**

A Russian-origin IP submitted commands including `gpon`, `linuxshell`, `7ujMko0admin`, `smcadmin`, `1q2w3e`. These are router-specific default credentials for GPON fiber routers (common in Eastern Europe and Asia), Zyxel, and Netgear devices. The scanner was not looking for Linux servers. It was looking for specific embedded devices with known default credentials.

**What the data shows**

The Telnet port in 2026 is not a relic. It is an active attack surface for three distinct populations: IoT botnets running hex-encoded authentication probes, router scanners with device-specific credential lists, and occasional human operators. The honeypot emulating a BusyBox router attracted all three simultaneously.
