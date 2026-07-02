#!/usr/bin/env python3
import json
from collections import defaultdict

LOGFILE = 'telnethoney.json'

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            try: yield json.loads(line)
            except: continue

def main():
    sessions = defaultdict(list)
    for e in safe_json_lines(LOGFILE):
        ip, cmd = e.get('src_ip'), e.get('command')
        if ip and cmd: sessions[ip].append(cmd)
    for ip, seq in sessions.items():
        if len(seq) > 1:
            print(f'\n=== Session from {ip} ===')
            for c in seq: print(' ', c)

if __name__ == '__main__': main()
