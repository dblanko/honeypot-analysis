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
    cmds = Counter()
    for e in safe_json_lines(LOGFILE):
        cmd = e.get('command')
        if cmd: cmds[cmd] += 1
    print('=== Telnet Commands ===')
    for c, n in cmds.most_common(10): print(f'{c}: {n}')

if __name__ == '__main__': main()
