#!/usr/bin/env python3
import sqlite3
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM connections;')
    print(f"Total connections: {cur.fetchone()[0]}")
    cur.execute('SELECT COUNT(DISTINCT remote_host) FROM connections;')
    print(f"Unique attacker IPs: {cur.fetchone()[0]}")
    cur.execute('''SELECT connection_type, COUNT(*) FROM connections
                   GROUP BY connection_type ORDER BY COUNT(*) DESC;''')
    print("\nConnection types:")
    for t, c in cur.fetchall(): print(f"  {t}: {c}")
    cur.execute('''SELECT connection_protocol, COUNT(*) FROM connections
                   WHERE connection_type=\'accept\'
                   GROUP BY connection_protocol ORDER BY COUNT(*) DESC;''')
    print("\nProtocols:")
    for t, c in cur.fetchall(): print(f"  {t}: {c}")
    conn.close()
if __name__ == '__main__': main()
