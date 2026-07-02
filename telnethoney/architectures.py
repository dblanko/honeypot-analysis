#!/usr/bin/env python3
import json, re
from collections import Counter

LOGFILE = 'telnethoney.json'
arch_re = re.compile(r'\b(arm|mips|mpsl|x86|amd64|mipsel)\b', re.I)

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            try: yield json.loads(line)
            except: continue

def main():
    arch = Counter()
    for e in safe_json_lines(LOGFILE):
        cmd = e.get('command','')
        if cmd:
            for m in arch_re.findall(cmd): arch[m.lower()] += 1
    print('=== Architectures Targeted ===')
    for a, c in arch.most_common(): print(f'{a}: {c}')

if __name__ == '__main__': main()
