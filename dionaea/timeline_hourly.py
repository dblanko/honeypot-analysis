#!/usr/bin/env python3
import sqlite3
from collections import Counter
from datetime import datetime
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT connection_timestamp FROM connections
                   WHERE connection_type=\'accept\';''')
    hours = Counter()
    for (ts,) in cur.fetchall():
        if ts:
            try: hours[datetime.fromtimestamp(float(ts)).hour] += 1
            except: pass
    print("\n=== HOURLY ACTIVITY ===")
    for hour in range(24):
        print(f"{hour:02d}:00 - {hours[hour]}")
if __name__ == '__main__': main()
