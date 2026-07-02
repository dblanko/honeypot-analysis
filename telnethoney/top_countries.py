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
    by_c = Counter()
    for e in safe_json_lines(LOGFILE):
        by_c[e.get('geo',{}).get('country','Unknown')] += 1
    print('=== Top Countries ===')
    for c, n in by_c.most_common(10): print(f'{c}: {n}')

if __name__ == '__main__': main()
