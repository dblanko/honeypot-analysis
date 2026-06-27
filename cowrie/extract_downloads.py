#!/usr/bin/env python3
"""
extract_downloads.py — Group file downloads by SHA256.
Identifies coordinated campaigns when the same payload is delivered by multiple IPs.
"""
import json
import os
import subprocess
from collections import defaultdict

LOG_DIR = '/home/cowrie/cowrie/var/log/cowrie'
DOWNLOAD_DIR = '/home/cowrie/cowrie/var/lib/cowrie/downloads'

files = sorted([
    os.path.join(LOG_DIR, f)
    for f in os.listdir(LOG_DIR)
    if f.startswith('cowrie.json')
])

# sha256 -> {ips, urls, files}
downloads = defaultdict(lambda: {'ips': set(), 'urls': set(), 'files': set()})

print(f'[+] Processing {len(files)} log files...')

for f in files:
    with open(f, 'r', errors='ignore') as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except:
                continue
            if event.get('eventid') == 'cowrie.session.file_download':
                sha = event.get('shasum')
                if not sha:
                    continue
                downloads[sha]['ips'].add(event.get('src_ip', 'unknown'))
                url = event.get('url')
                if url:
                    downloads[sha]['urls'].add(url)
                fname = event.get('outfile', '')
                if fname:
                    downloads[sha]['files'].add(os.path.basename(fname))

# ── Terminal report ────────────────────────────────
print()
print(f'Total unique payloads (SHA256): {len(downloads)}')
print()

sorted_dl = sorted(downloads.items(), key=lambda x: len(x[1]['ips']), reverse=True)

for sha, info in sorted_dl:
    ip_count = len(info['ips'])
    print(f'SHA256:  {sha}')
    print(f'  IPs ({ip_count}): {sorted(info["ips"])}')
    print(f'  URLs:      {sorted(info["urls"])}')
    print(f'  Files:     {sorted(info["files"])}')
    print()

# ── Detect file type using `file` command ────────────────────────────────
def detect_file_type(path):
    try:
        out = subprocess.check_output(['file', path], text=True)
        return out.split(':', 1)[1].strip()
    except:
        return "Unknown"

def detect_arch(ftype):
    t = ftype.lower()
    if 'x86-64' in t or 'x86_64' in t: return 'x86_64'
    if '80386'  in t or 'i386'   in t: return 'x86'
    if 'aarch64'in t:                   return 'ARM64'
    if 'arm'    in t:                   return 'ARM'
    if 'mips'   in t:                   return 'MIPS'
    if 'shell script' in t:             return 'Shell script'
    return 'Other'

# ── Save malware_files.json ─────────────────────────────────────────────
files_out = []

for sha, info in downloads.items():
    filenames = sorted(info["files"])
    primary_filename = filenames[0] if filenames else None

    full_path = os.path.join(DOWNLOAD_DIR, sha) if primary_filename else None

    if full_path and os.path.exists(full_path):
        ftype = detect_file_type(full_path)
        arch  = detect_arch(ftype)
    else:
        ftype = "Unknown"
        arch  = "Unknown"

    files_out.append({
        "sha256": sha,
        "filename": primary_filename,
        "ips": sorted(info["ips"]),
        "urls": sorted(info["urls"]),
        "file_type": ftype,
        "arch": arch
    })

with open("malware_files.json", "w") as f:
    json.dump(files_out, f, indent=2)

print("[+] Saved: malware_files.json")
print('[+] Done.')
