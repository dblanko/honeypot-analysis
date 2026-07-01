#!/usr/bin/env python3
import sqlite3, geoip2.database
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
GEO_DB  = "/var/lib/GeoIP/GeoLite2-Country.mmdb"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT remote_host FROM connections;')
    ips = [row[0] for row in cur.fetchall()]
    reader = geoip2.database.Reader(GEO_DB)
    countries = {}
    for ip in ips:
        try: c = reader.country(ip).country.iso_code or 'Unknown'
        except: c = 'Unknown'
        countries[c] = countries.get(c, 0) + 1
    reader.close()
    print("\n=== ATTACKER COUNTRIES ===")
    for c, n in sorted(countries.items(), key=lambda x: x[1], reverse=True):
        print(f"{c}: {n}")
if __name__ == '__main__': main()
