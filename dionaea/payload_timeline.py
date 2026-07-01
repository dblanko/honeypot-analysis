#!/usr/bin/env python3
import sqlite3
from collections import Counter
from datetime import datetime
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT d.download_md5_hash, c.connection_timestamp
                   FROM downloads d
                   JOIN connections c ON d.connection = c.connection;''')
    timestamps = []
    for _, ts in cur.fetchall():
        if ts:
            try: timestamps.append(datetime.fromtimestamp(float(ts)))
            except: pass
    days  = Counter([dt.date() for dt in timestamps])
    hours = Counter([dt.hour for dt in timestamps])
    print("\n=== BY DAY ===")
    for day, c in sorted(days.items()):
        print(f"{day}: {c}")
    print("\n=== BY HOUR ===")
    for hour, c in sorted(hours.items()):
        print(f"{hour:02d}:00 - {c}")
if __name__ == '__main__': main()
