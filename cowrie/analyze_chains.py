#!/usr/bin/env python3
"""
analyze_chains.py — Attack chain reconstruction.
Joins upload + command + file-type data by source IP.
Requires: malware_uploads.json, malware_commands.json, malware_files.json
"""
import os
import json
import csv
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
from datetime import datetime

PLOTS_DIR = os.path.expanduser('~/malware_plots/chains')
os.makedirs(PLOTS_DIR, exist_ok=True)

# ── Load inputs ─────────────────────────────────────────────────────────────
with open('malware_uploads.json')  as f: uploads   = json.load(f)
with open('malware_commands.json') as f: commands  = json.load(f)
with open('malware_files.json')    as f: files_info= json.load(f)

# ── File type index ─────────────────────────────────────────────────────────
file_types = {}
file_arch  = {}

def detect_arch(t):
    t = t.lower()
    if 'x86-64' in t or 'x86_64' in t: return 'x86_64'
    if '80386'  in t or 'i386'   in t: return 'x86'
    if 'aarch64'in t:                   return 'ARM64'
    if 'arm'    in t:                   return 'ARM'
    if 'shell script' in t:             return 'Shell script'
    if 'mips' in t:                     return 'MIPS'
    return 'Other'

for fi in files_info:
    sha = fi['filename']
    file_types[sha] = fi.get('file_type', 'Unknown')
    file_arch[sha]  = fi.get('arch', 'Unknown')

# ── Group commands by IP ─────────────────────────────────────────────────────
commands_by_ip = defaultdict(list)
for c in commands:
    commands_by_ip[c['src_ip']].append(c)

# ── Build chains ────────────────────────────────────────────────────────────
chains = []
arch_stats = Counter()
file_stats = Counter()
ip_stats   = Counter()

for u in uploads:
    ip       = u['src_ip']
    sha      = u['sha256']
    filename = u['filename']
    ts       = u['timestamp']
    arch     = file_arch.get(sha, 'Unknown')
    ftype    = file_types.get(sha, 'Unknown')
    ip_cmds  = [c['command'] for c in commands_by_ip[ip]]

    chains.append({
        'src_ip':    ip,
        'timestamp': ts,
        'filename':  filename,
        'sha256':    sha,
        'arch':      arch,
        'file_type': ftype,
        'commands':  ip_cmds,
    })
    arch_stats[arch]    += 1
    file_stats[filename]+= 1
    ip_stats[ip]        += 1

print("\n=== Attack Chains ===\n")

for chain in chains:
    print(f"Source IP:   {chain.get('src_ip')}")
    print(f"Timestamp:   {chain.get('timestamp')}")
    print(f"Filename:    {chain.get('filename')}")
    print(f"SHA256:      {chain.get('sha256')}")
    print(f"Arch:        {chain.get('arch')}")
    print(f"File type:   {chain.get('file_type')}")
    print(f"Commands:    {len(chain.get('commands', []))} commands")
    print("-" * 60)


# ── Save outputs ────────────────────────────────────────────────────────────
with open('malware_chains.json', 'w') as f:
    json.dump(chains, f, indent=2, default=str)

with open('malware_chains.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['src_ip','timestamp','filename','sha256','arch','file_type'])
    w.writeheader()
    for c in chains:
        w.writerow({k: c[k] for k in ['src_ip','timestamp','filename','sha256','arch','file_type']})

# ── Charts ──────────────────────────────────────────────────────────────────
for data, title, fname, color in [
    (arch_stats,  'Architectures by attack count', 'chains_architectures.png', 'green'),
    (file_stats,  'Top downloaded files',          'chains_files.png',         'blue'),
    (ip_stats,    'Top IPs by malicious chains',   'chains_ips.png',            'purple'),
]:
    if data:
        labels, values = zip(*data.most_common(15))
        plt.figure(figsize=(12, 8))
        plt.barh(labels, values, color=color)
        plt.title(title)
        plt.tight_layout()
        plt.savefig(f'{PLOTS_DIR}/{fname}')
        plt.close()

print('[+] Chain analysis completed.')
print('[+] Files: malware_chains.json, malware_chains.csv')
print(f'[+] Charts saved to {PLOTS_DIR}/')
