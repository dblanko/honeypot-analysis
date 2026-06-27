#!/usr/bin/env python3
"""
analyze_payloads.py — Static analysis of Cowrie downloaded payloads.
Extracts architecture, entropy, IoC strings. Never executes binaries.
"""
import os, json, csv, math, re, subprocess
from pathlib import Path

DOWNLOADS_DIR = Path('/home/cowrie/cowrie/var/lib/cowrie/downloads')

def run(cmd):
    """Run a shell command, return stdout string."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as e:
        return f'ERROR: {e}'

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data (0–8)."""
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_iocs(strings_output: str) -> dict:
    """Extract IoC patterns from strings output."""
    ipv4  = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', strings_output)
    urls  = re.findall(r'https?://[\w./:-]+', strings_output)
    doms  = re.findall(r'\b[a-z0-9-]+\.(?:com|net|org|io|cc|ru|cn)\b', strings_output)
    xmr   = re.findall(r'4[0-9AB][0-9a-fA-F]{93}', strings_output)
    ports = re.findall(r':\d{4,5}\b', strings_output)
    return {'ipv4': list(set(ipv4)), 'urls': list(set(urls)),
            'domains': list(set(doms)), 'xmr_wallets': list(set(xmr)),
            'c2_ports': list(set(ports))}

results = []

payload_files = [f for f in DOWNLOADS_DIR.iterdir()
                 if f.is_file() and not f.name.endswith('.json')]

print(f'[+] Analysing {len(payload_files)} payloads...')

for fp in payload_files:
    print(f'  -> {fp.name}')
    data = fp.read_bytes()
    size = len(data)

    file_type = run(['file', '-b', str(fp)])
    upx_info  = run(['upx', '-l', str(fp)])
    strings_out = run(['strings', '-n', '6', str(fp)])
    elf_sections= run(['readelf', '-S', str(fp)])

    # Architecture detection
    arch = 'unknown'
    for marker, label in [
        ('x86-64','x86_64'), ('80386','x86'), ('ARM aarch64','ARM64'),
        ('ARM,','ARM'),      ('MIPS','MIPS'),  ('PowerPC','PowerPC'),
        ('shell script','shell'),
    ]:
        if marker.lower() in file_type.lower():
            arch = label
            break

    is_upx = 'upx' in upx_info.lower() and 'not packed' not in upx_info.lower()
    entropy = shannon_entropy(data)
    iocs = extract_iocs(strings_out)

    results.append({
        'filename':     fp.name,
        'size_bytes':   size,
        'file_type':    file_type[:100],
        'architecture': arch,
        'upx_packed':   is_upx,
        'entropy':      entropy,
        'iocs':         iocs,
        'elf_sections': elf_sections[:500] if elf_sections else '',
    })

# ── Save outputs ─────────────────────────────────────────────────────────────
with open('payload_analysis.json', 'w') as f:
    json.dump(results, f, indent=2)

with open('payload_summary.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=
        ['filename','size_bytes','architecture','upx_packed','entropy',
         'iocs_ipv4','iocs_urls'])
    w.writeheader()
    for r in results:
        w.writerow({
            'filename':     r['filename'],
            'size_bytes':   r['size_bytes'],
            'architecture': r['architecture'],
            'upx_packed':   r['upx_packed'],
            'entropy':      r['entropy'],
            'iocs_ipv4':    '|'.join(r['iocs']['ipv4']),
            'iocs_urls':    '|'.join(r['iocs']['urls']),
        })

print(f'[+] Results saved: payload_analysis.json, payload_summary.csv')
print()
print('=== Summary ===')
for r in results:
    flags = []
    if r['upx_packed']:    flags.append('UPX')
    if r['entropy'] > 7.0: flags.append(f'HIGH-ENTROPY({r["entropy"]})')
    if r['iocs']['ipv4']:  flags.append(f'IoC-IP:{r["iocs"]["ipv4"][0]}')
    if r['iocs']['xmr_wallets']: flags.append('XMR-WALLET')
    flag_str = ' '.join(flags) if flags else '-'
    print(f'  {r["filename"]:<40} {r["architecture"]:<8} {flag_str}')
