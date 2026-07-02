import socket
import threading
import json
import time
import random
import os
from datetime import datetime, timezone

import http.server
import socketserver
import requests

BANNER = "BusyBox v1.01 (ash)\n"
LOGFILE = "/home/honeypotuser/telnet-honey/logs/telnethoney.json"

CPU_MODELS = [
    "Atheros AR9330 rev 1",
    "MediaTek MT7620A",
    "Qualcomm Atheros QCA9531",
    "MIPS 24Kc V7.4",
    "ARMv7 Processor rev 5"
]

HOSTNAMES = [
    "OpenWrt",
    "TP-Link",
    "D-Link",
    "MikroTik",
    "RouterOS"
]

FAKE_PS = """PID   USER     COMMAND
1     root     init
23    root     telnetd
42    root     sh
73    root     dropbear
101   root     kworker/0:1
1337  root     mirai
2048  root     mozi
"""

FAKE_TOP = """top - 17:42:01 up 3 days,  4:12,  load average: 0.00, 0.01, 0.05
Tasks:  25 total,   1 running,  24 sleeping,   0 stopped,   0 zombie
Cpu(s):  2.0%us,  1.0%sy,  0.0%ni, 96.0%id,  1.0%wa,  0.0%hi,  0.0%si,  0.0%st
Mem:     29184k total,    10240k used,    18944k free,     2048k buffers
PID   USER     PR  NI  VIRT   RES   SHR S %CPU %MEM     TIME+ COMMAND
1     root     0   0  1024   512   512 S  0.0  1.7   0:01.23 init
23    root     0   0  1024   512   512 S  0.3  1.7   0:03.45 telnetd
42    root     0   0  1024   512   512 S  0.1  1.7   0:00.98 sh
73    root     0   0  1024   512   512 S  0.2  1.7   0:02.11 dropbear
1337  root     0   0  1024   512   512 S  0.5  1.7   0:10.01 mirai
"""

FAKE_DF = """Filesystem           Size  Used Avail Use% Mounted on
/dev/root            4.0M  3.1M  0.9M  78% /
tmpfs                14M   0     14M   0% /tmp
/dev/mtdblock3       16M   8M    8M   50% /overlay
overlayfs:/overlay   16M   8M    8M   50% /
"""

FAKE_SHADOW = """root:$1$xyz$abcdefabcdefabcdefabcdef.:10933:0:99999:7:::
admin:$1$xyz$abcdefabcdefabcdefabcdef.:10933:0:99999:7:::
"""

FAKE_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0017 0200000A:CF19 01 00000000:00000000 00:00000000 00000000   0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0300000A:D204 01 00000000:00000000 00:00000000 00000000   0        0 12346 1 0000000000000000 100 0 0 10 0
"""


# -------- GEO / IP Classification --------

def get_geo(ip: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting"
        r = requests.get(url, timeout=2)
        data = r.json()
        if data.get("status") != "success":
            return {}
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
        }
    except Exception:
        return {}


def classify_ip(geo: dict) -> str:
    if not geo:
        return "unknown"
    isp = (geo.get("isp") or "").lower()
    org = (geo.get("org") or "").lower()
    asn = (geo.get("as") or "").lower()
    if "tor" in isp or "tor" in org or "tor" in asn:
        return "tor"
    if geo.get("proxy") or geo.get("hosting"):
        return "vpn_or_hosting"
    return "residential_or_unknown"


# -------- LOGGING --------

def log_event(ip, username=None, password=None, command=None,
              http_method=None, http_path=None, user_agent=None):
    geo = get_geo(ip)
    ip_class = classify_ip(geo)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": ip,
        "geo": geo,
        "ip_class": ip_class,
        "username": username,
        "password": password,
        "command": command,
        "http_method": http_method,
        "http_path": http_path,
        "user_agent": user_agent,
    }
    try:
        os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass


# -------- AUXILIARY FUNCTIONS --------

def random_mac():
    oui = random.choice([
        "F4:EC:38",  # TP-Link
        "C0:25:E9",  # D-Link
        "E8:94:F6",  # Zyxel
        "00:1A:2B",  # Huawei
        "4C:5E:0C"   # MikroTik
    ])
    last = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{last}"


def random_ip():
    choice = random.randint(1, 3)
    if choice == 1:
        return f"192.168.{random.randint(0, 254)}.1"
    if choice == 2:
        return f"10.{random.randint(0, 254)}.{random.randint(0, 254)}.1"
    return f"172.16.{random.randint(0, 254)}.1"


def random_uptime():
    days = random.randint(0, 30)
    hours = random.randint(0, 23)
    minutes = random.randint(0, 59)
    return f"up {days} days, {hours}:{minutes:02d}"


def random_meminfo():
    total = random.randint(16000, 64000)
    free = random.randint(2000, total - 4000)
    return f"MemTotal:        {total} kB\nMemFree:         {free} kB\n"


# -------- PROCESSING COMMANDS --------

def handle_echo_redirection(cmd, state):
    # echo "text" > file  /  echo text >> file
    if not cmd.strip().startswith("echo "):
        return None, state

    if ">>" in cmd:
        sep = ">>"
        append = True
    elif ">" in cmd:
        sep = ">"
        append = False
    else:
        return None, state

    left, right = cmd.split(sep, 1)
    content = left[len("echo "):].strip()
    if (content.startswith('"') and content.endswith('"')) or (content.startswith("'") and content.endswith("'")):
        content = content[1:-1]
    path = right.strip()

    if not path:
        return None, state

    old = state["files"].get(path, "") if append else ""
    state["files"][path] = old + content + "\n"
    return "", state


def handle_command(cmd, state):
    # echo с перенаправлением
    res, state = handle_echo_redirection(cmd, state)
    if res is not None:
        return res, state

    parts = cmd.split()
    if not parts:
        return "", state

    c = parts[0]

    # ls
    if c == "ls":
        if len(parts) > 1 and parts[1] == "/etc/init.d":
            return "rcS\nnetwork\ntelnetd\n", state
        return "bin  etc  tmp  usr  var  root  proc\n", state

    # ifconfig
    if c == "ifconfig":
        return (
            f"eth0      Link encap:Ethernet  HWaddr {state['mac']}\n"
            f"          inet addr:{state['ip']}  Mask:255.255.255.0\n"
            f"          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
        ), state

    # uname
    if c == "uname":
        return f"Linux {state['hostname']} 2.6.32 {state['cpu']}\n", state

    # uptime
    if c == "uptime":
        return f" {state['uptime']}, load average: 0.00, 0.01, 0.05\n", state

    # df
    if c == "df":
        return FAKE_DF, state

    # ps
    if c == "ps":
        return FAKE_PS, state

    # top
    if c == "top":
        return FAKE_TOP, state

    # cat
    if c == "cat":
        if len(parts) > 1:
            path = parts[1]
            if path == "/proc/cpuinfo":
                return f"system type : {state['cpu']}\n", state
            if path == "/proc/meminfo":
                return random_meminfo(), state
            if path == "/etc/banner":
                return f"{state['hostname']} Firmware v1.0\n", state
            if path == "/etc/shadow":
                return FAKE_SHADOW, state
            if path == "/proc/net/tcp":
                return FAKE_TCP, state
            if path in state["files"]:
                return state["files"][path], state
        return f"cat: {parts[1]}: No such file or directory\n", state

    # busybox
    if c == "busybox":
        if len(parts) == 1:
            return "BusyBox v1.01 (ash) multi-call binary\n", state
        sub = parts[1]
        return f"BusyBox: applet not found: {sub}\n", state

    # wget / curl
    if c in ["wget", "curl"]:
        if len(parts) > 1:
            url = parts[1]
            return (
                f"Connecting to {url}...  failed: Network unreachable\n",
                state
            )
        return f"{c}: missing URL\n", state

    # chmod (no-op)
    if c == "chmod":
        return "", state

    # improved ping
    if c == "ping":
        if len(parts) < 2:
            return "ping: missing host\n", state

        host = parts[1]
        count = random.randint(3, 5)
        output = f"PING {host}: 56 data bytes\n"

        lost = random.randint(0, 1)
        delivered = count - lost

        lost_index = random.randint(0, count - 1) if lost else -1

        for i in range(count):
            if i == lost_index:
                output += f"Request timeout for icmp_seq={i}\n"
                time.sleep(random.uniform(0.05, 0.15))
                continue

            time_ms = round(random.uniform(1.0, 12.0), 2)
            ttl = random.choice([62, 63, 64])
            output += (
                f"64 bytes from {host}: icmp_seq={i} ttl={ttl} time={time_ms} ms\n"
            )
            time.sleep(random.uniform(0.05, 0.15))

        output += "--- ping statistics ---\n"
        loss_pct = int((lost / count) * 100)
        output += f"{count} packets transmitted, {delivered} packets received, {loss_pct}% packet loss\n"

        return output, state

    # netstat
    if c == "netstat":
        return (
            "Active Internet connections (w/o servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            f"tcp        0      0 {state['ip']}:23         45.9.148.2:53421        ESTABLISHED\n"
            f"tcp        0      0 {state['ip']}:80         91.198.174.192:443      ESTABLISHED\n"
        ), state

    # /etc/init.d scripts
    if c.startswith("/etc/init.d/"):
        return "", state

    # exit / logout / reboot
    if c in ["exit", "logout", "reboot"]:
        return "__EXIT__", state

    # fallback
    return f"sh: {cmd}: not found\n", state


# -------- TELNET --------

def handle_client(conn, addr):
    ip = addr[0]

    state = {
        "mac": random_mac(),
        "ip": random_ip(),
        "cpu": random.choice(CPU_MODELS),
        "hostname": random.choice(HOSTNAMES),
        "uptime": random_uptime(),
        "files": {}  # virtual files (echo >, wget и т.п.)
    }

    try:
        conn.sendall(BANNER.encode())
        conn.sendall(b"login: ")
        username = conn.recv(1024).decode(errors="ignore").strip()

        conn.sendall(b"Password: ")
        password = conn.recv(1024).decode(errors="ignore").strip()

        log_event(ip, username=username, password=password)

        conn.sendall(b"\nWelcome to BusyBox shell\n")
        conn.sendall(b"# ")

        while True:
            cmd = conn.recv(1024)
            if not cmd:
                break

            cmd = cmd.decode(errors="ignore").strip()
            log_event(ip, command=cmd)

            output, state = handle_command(cmd, state)

            if output == "__EXIT__":
                break

            time.sleep(0.2)
            conn.sendall(output.encode())
            conn.sendall(b"# ")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_server(port=2323):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(50)
    print(f"Telnet honeypot listening on port {port}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


# -------- HTTP --------

class FakeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # suppress the standard stdout log
        return

    def do_GET(self):
        ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "")
        log_event(
            ip,
            http_method="GET",
            http_path=self.path,
            user_agent=ua,
        )

        # If a bot downloads a binary, we pretend everything is fine
        if any(self.path.endswith(ext) for ext in [
            ".sh", ".bin", ".elf", ".mips", ".arm", ".mpsl", ".mozi"
        ]):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(b"#!/bin/sh\necho 'OK'\n")
            return

        # Router home page
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>OpenWrt Web Interface</h1></body></html>")
            return

        # Everything else is 404
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")


def start_http_server():
    PORT = 8080
    handler = FakeHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), handler)
    print(f"Fake HTTP server listening on port {PORT}")
    httpd.serve_forever()


# -------- MAIN --------

if __name__ == "__main__":
    threading.Thread(target=start_http_server, daemon=True).start()
    start_server()
