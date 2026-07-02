#!/usr/bin/env python3
import json
from collections import defaultdict

LOGFILE = 'telnethoney.json'

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            try: yield json.loads(line)
            except: continue

def classify(entry):
    if entry.get('command'):
        cmd = entry['command'].lower()
        if 'wget' in cmd or 'curl' in cmd: return 'Downloader'
        if 'busybox' in cmd: return 'Botnet Loader'
        if 'chmod' in cmd or './' in cmd: return 'Malware Execution'
        return 'Interactive Shell'
    if entry.get('username') or entry.get('password'): return 'Credential Brute Force'
    if entry.get('http_method'): return 'HTTP Scanner'
    return 'Unknown'

def main():
    profiles = defaultdict(int)
    for e in safe_json_lines(LOGFILE): profiles[classify(e)] += 1
    print('=== Attacker Profiles ===')
    for p, c in sorted(profiles.items(), key=lambda x: -x[1]): print(f'{p}: {c}')

if __name__ == '__main__': main()
