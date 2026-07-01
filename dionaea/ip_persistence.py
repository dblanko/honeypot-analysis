#!/usr/bin/env python3
import sqlite3, datetime
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT remote_host, connection_timestamp FROM connections;')
    ip_days = {}
    for ip, ts in cur.fetchall():
        if ts:
            if isinstance(ts, (int, float)):
                dt = datetime.datetime.fromtimestamp(ts, datetime.UTC)

        elif isinstance(ts, str):
            try:
                dt = datetime.datetime.fromtimestamp(float(ts), datetime.UTC)
            except ValueError:
                dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))

        else:
            raise ValueError(f"Unknown timestamp format: {ts}")

        day = dt.strftime('%Y-%m-%d')
        ip_days.setdefault(ip, set()).add(day)

    persistent = {ip: days for ip, days in ip_days.items() if len(days) > 1}
    print("\n=== PERSISTENT ATTACKERS ===")
    for ip, days in sorted(persistent.items(),
                           key=lambda x: len(x[1]), reverse=True):
        print(f"{ip}: {len(days)} days -> {sorted(days)}")
if __name__ == '__main__': main()
