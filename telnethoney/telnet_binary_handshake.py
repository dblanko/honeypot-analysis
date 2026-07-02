#!/usr/bin/env python3
import json, re

LOGFILE = 'telnethoney.json'
binary_re = re.compile(r'\\u00[0-9a-f]{2}')

def safe_json_lines(path):
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        for i, line in enumerate(f, 1):
            try: yield i, json.loads(line)
            except: continue

def main():
    print('=== Binary Handshake Entries ===')
    for lineno, e in safe_json_lines(LOGFILE):
        if binary_re.search(json.dumps(e)):
            print(f'Line {lineno}: {e.get("src_ip")}')

if __name__ == '__main__': main()
