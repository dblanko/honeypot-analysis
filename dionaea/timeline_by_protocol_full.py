#!/usr/bin/env python3
import sqlite3
from collections import defaultdict, Counter
from datetime import datetime
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT connection_protocol, connection_timestamp
                   FROM connections WHERE connection_timestamp IS NOT NULL;''')
    proto_hours = defaultdict(Counter)
    for proto, ts in cur.fetchall():
        if not proto or not ts: continue
        try: proto_hours[proto][datetime.fromtimestamp(float(ts)).hour] += 1
        except: pass
    print("\n=== HOURLY ACTIVITY BY PROTOCOL ===")
    for proto, hours in proto_hours.items():
        print(f"\nProtocol: {proto}")
        for hour in range(24):
            print(f"  {hour:02d}:00 - {hours[hour]}")
if __name__ == '__main__': main()
