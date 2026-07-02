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
    classes = Counter()
    for e in safe_json_lines(LOGFILE):
        classes[e.get('ip_class','Unknown')] += 1
    print('=== IP Classes ===')
    for c, n in classes.most_common(): print(f'{c}: {n}')

if __name__ == '__main__': main()
