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
    hours = Counter()
    for e in safe_json_lines(LOGFILE):
        if e.get('command'):
            hours[e.get('timestamp','')[:13]] += 1
    print('=== Command Activity by Hour ===')
    for h, c in hours.most_common(): print(h, c)

if __name__ == '__main__': main()
