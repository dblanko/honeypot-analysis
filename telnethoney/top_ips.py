#!/usr/bin/env python3
import json
from collections import Counter

LOGFILE = 'telnethoney.json'

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            try: yield json.loads(line)
            except: continue

def main():
    by_ip = Counter()
    for entry in safe_json_lines(LOGFILE):
        by_ip[entry.get('src_ip','unknown')] += 1
    print('=== Top IPs ===')
    for ip, count in by_ip.most_common(10): print(f'{ip}: {count}')

if __name__ == '__main__': main()
