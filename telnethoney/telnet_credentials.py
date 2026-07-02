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
    users, passwords, combos = Counter(), Counter(), Counter()
    for e in safe_json_lines(LOGFILE):
        u, p = e.get('username'), e.get('password')
        if u: users[u] += 1
        if p: passwords[p] += 1
        if u or p: combos[f'{u}:{p}'] += 1
    print('=== Top Usernames ===')
    for u, c in users.most_common(10): print(u, c)
    print('\n=== Top Passwords ===')
    for p, c in passwords.most_common(10): print(p, c)
    print('\n=== Top Credential Pairs ===')
    for cp, c in combos.most_common(10): print(cp, c)

if __name__ == '__main__': main()
