import json
from collections import Counter

LOGFILE = "period.json"
rdp_total = rdp_null = rdp_empty = rdp_real = rdp_pwd = rdp_dom = 0
rdp_users = Counter()

with open(LOGFILE) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: event = json.loads(line)
        except: continue
        if event.get("logtype") != 14001: continue
        rdp_total += 1
        ld = event.get("logdata", {})
        u  = ld.get("USERNAME") if isinstance(ld, dict) else None
        if ld.get("PASSWORD"): rdp_pwd += 1
        if ld.get("DOMAIN"):   rdp_dom += 1
        if u is None:  rdp_null  += 1
        elif u == "": rdp_empty += 1
        else:
            rdp_real += 1
            rdp_users[u] += 1

print(f"Total RDP events:  {rdp_total}")
print(f"USERNAME = null:   {rdp_null}  ({rdp_null/rdp_total*100:.1f}%)")
print(f"USERNAME = empty:  {rdp_empty} ({rdp_empty/rdp_total*100:.1f}%)")
print(f"USERNAME = value:  {rdp_real}  ({rdp_real/rdp_total*100:.1f}%)")
print(f"DOMAIN present:    {rdp_dom}")
print(f"PASSWORD present:  {rdp_pwd}")
if rdp_pwd == 0:
    print("  >>> No passwords in RDP logs (NLA/CredSSP by design)")
print("\nTop 10 usernames:")
for u, n in rdp_users.most_common(10):
    print(f"  {u:<10} {n}")
