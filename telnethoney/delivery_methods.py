#!/usr/bin/env python3
import json, re
from collections import Counter

LOGFILE = 'telnethoney.json'
patterns = {
    'wget': re.compile(r'\bwget\b', re.I),
    'curl': re.compile(r'\bcurl\b', re.I),
    'busybox wget': re.compile(r'busybox wget', re.I),
    'busybox curl': re.compile(r'busybox curl', re.I),
    'nc':   re.compile(r'\bnc\b', re.I),
    'toybox nc': re.compile(r'toybox nc', re.I),
    'socat': re.compile(r'\bsocat\b', re.I),
    'tftp':  re.compile(r'\btftp\b', re.I),
    'base64': re.compile(r'base64 -d', re.I),
    'bash tcp': re.compile(r'/dev/tcp', re.I),
}

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            try: yield json.loads(line)
            except: continue

def main():
    counts = Counter()
    for e in safe_json_lines(LOGFILE):
        cmd = e.get('command','')
        if not cmd: continue
        for name, regex in patterns.items():
            if regex.search(cmd): counts[name] += 1
    print('=== Delivery Methods ===')
    for method, count in counts.most_common(): print(f'{method}: {count}')

if __name__ == '__main__': main()
