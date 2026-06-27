#!/usr/bin/env python3
"""
attacker_profiling.py — Per-IP attacker profiling.
Calculates risk scores and maps behaviour to MITRE ATT&CK.
"""
import pandas as pd
from collections import Counter


class AttackerProfiler:

    def __init__(self, df: pd.DataFrame, creds: pd.DataFrame):
        self.df = df
        self.creds = creds
        self.profiles = self._build_profiles()

    def attackers(self):
        """Return list of unique attacker IPs."""
        return self.df['src_ip'].dropna().unique().tolist()

    def sessions_by_ip(self, ip):
        return self.df[self.df['src_ip'] == ip]['session'].dropna().unique().tolist()

    def commands_by_ip(self, ip):
        mask = (self.df['src_ip'] == ip) & (self.df['eventid'] == 'cowrie.command.input')
        return self.df[mask]['input'].dropna().tolist()

    def successful_logins_by_ip(self, ip):
        if self.creds.empty:
            return []
        return self.creds[
            (self.creds['src_ip'] == ip) & (self.creds['success'] == True)
        ].to_dict('records')

    def _is_interactive(self, cmds):
        """More than 10 unique commands suggests a human operator."""
        return len(set(cmds)) > 10

    def _is_botnet_like(self, cmds):
        """Single command repeated >5 times — automated injection loop."""
        if not cmds:
            return False
        return Counter(cmds).most_common(1)[0][1] > 5

    def _is_recon(self, cmds):
        """Session contains system discovery commands."""
        keywords = ['uname', 'whoami', 'hostname', 'cat /proc', 'ls ', 'pwd', 'ifconfig']
        joined = ' '.join(cmds).lower()
        return any(k in joined for k in keywords)

    def _build_profiles(self):
        rows = []
        for ip in self.attackers():
            cmds = self.commands_by_ip(ip)
            rows.append({
                'ip':               ip,
                'total_sessions':   len(self.sessions_by_ip(ip)),
                'total_commands':   len(cmds),
                'unique_commands':  len(set(cmds)),
                'top_commands':     Counter(cmds).most_common(5),
                'successful_logins':len(self.successful_logins_by_ip(ip)),
                'is_interactive':   self._is_interactive(cmds),
                'is_botnet_like':   self._is_botnet_like(cmds),
                'is_recon_heavy':   self._is_recon(cmds),
            })
        return pd.DataFrame(rows)

    def map_to_mitre(self, row):
        """Map a profile row to MITRE ATT&CK technique IDs."""
        mitre = [('T1110', 'Brute Force')]
        if row['is_botnet_like']:
            mitre.append(('T1059', 'Command Execution'))
            mitre.append(('T1105', 'Ingress Tool Transfer'))
        if row['is_recon_heavy']:
            mitre.append(('T1082', 'System Information Discovery'))
            mitre.append(('T1046', 'Network Service Scanning'))
        if row['successful_logins'] > 0:
            mitre.append(('T1078', 'Valid Accounts'))
        if row['is_interactive']:
            mitre.append(('T1053', 'Scheduled Task/Job'))
            mitre.append(('T1059.004', 'Interactive Shell'))
        return mitre

    def risk_score(self, row):
        """Composite risk score (higher = more dangerous)."""
        score = row['total_commands']
        score += row['successful_logins'] * 5
        if row['is_botnet_like']:  score += 20
        if row['is_interactive']:  score += 30
        if row['is_recon_heavy']:  score += 10
        return score

    def full_report(self):
        """Return ranked DataFrame with risk scores and MITRE mappings."""
        rows = []
        for _, row in self.profiles.iterrows():
            rows.append({
                'ip':               row['ip'],
                'risk_score':       self.risk_score(row),
                'mitre_techniques': self.map_to_mitre(row),
                'total_commands':   row['total_commands'],
                'successful_logins':row['successful_logins'],
                'is_botnet_like':   row['is_botnet_like'],
                'is_interactive':   row['is_interactive'],
                'is_recon_heavy':   row['is_recon_heavy'],
            })
        return pd.DataFrame(rows).sort_values('risk_score', ascending=False)


if __name__ == '__main__':
    import sys
    from log_loader import CowrieLogLoader
    log_path = sys.argv[1] if len(sys.argv) > 1 else \
               '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    loader = CowrieLogLoader(log_path)
    df = loader.load_json()
    creds = loader.extract_credentials(df)
    report = AttackerProfiler(df, creds).full_report()
    print(report[['ip','risk_score','total_commands','successful_logins']].head(20).to_string())
