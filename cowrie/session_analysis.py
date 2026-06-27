#!/usr/bin/env python3
"""
session_analysis.py — Session-level behavioral analysis.
Reconstructs what attackers did inside each session.
"""
import pandas as pd
from collections import Counter


class SessionAnalyzer:
    """Analyze attacker behavior inside Cowrie sessions."""

    def __init__(self, df_events: pd.DataFrame):
        self.df = df_events

    def list_sessions(self):
        """Return all unique session IDs."""
        return self.df['session'].dropna().unique()

    def session_events(self, session_id):
        """Return all events for a single session, sorted by time."""
        return self.df[self.df['session'] == session_id].sort_values('timestamp')

    def command_events(self):
        """Return only cowrie.command.input events."""
        return self.df[self.df['eventid'] == 'cowrie.command.input']

    def commands_by_session(self):
        """Return number of commands per session, descending."""
        cmds = self.command_events()
        return cmds.groupby('session').size().sort_values(ascending=False)

    def top_commands(self, n=10):
        """Return most frequently executed commands across all sessions."""
        return self.command_events()['input'].value_counts().head(n)

    def longest_sessions(self, n=10):
        """
        Return sessions sorted by duration (time of last event minus first event).
        Requires 'timestamp' column.
        """
        durations = {}
        for sid in self.list_sessions():
            events = self.session_events(sid)
            if len(events) < 2:
                continue
            duration = events['timestamp'].max() - events['timestamp'].min()
            durations[sid] = duration
        return sorted(durations.items(), key=lambda x: x[1], reverse=True)[:n]

    def suspicious_sessions(self):
        """
        Return sessions containing suspicious commands:
        wget, curl, chmod, python, sh, bash -i
        """
        keywords = ['wget', 'curl', 'chmod', 'python', ' sh ', 'bash -i', '/tmp']
        cmds = self.command_events()
        mask = cmds['input'].str.contains('|'.join(keywords), na=False)
        return cmds[mask]['session'].unique()

    def session_summary(self, session_id):
        """Return a dict summary of a single session."""
        events = self.session_events(session_id)
        cmds = events[events['eventid'] == 'cowrie.command.input']['input'].tolist()
        logins_ok = events[events['eventid'] == 'cowrie.login.success']
        downloads = events[events['eventid'] == 'cowrie.session.file_download']
        src_ip = events['src_ip'].dropna().iloc[0] if 'src_ip' in events.columns else 'unknown'
        duration = (events['timestamp'].max() - events['timestamp'].min())
        return {
            'session_id':      session_id,
            'src_ip':          src_ip,
            'duration':        str(duration),
            'total_events':    len(events),
            'commands':        cmds,
            'command_count':   len(cmds),
            'logins_success':  len(logins_ok),
            'download_count':  len(downloads),
        }

    def full_report(self, top_n=10):
        """Print a full session analysis report to stdout."""
        print(f'=== Total sessions: {len(self.list_sessions())} ===')
        print()
        print('=== Top sessions by command count ===')
        for sid, cnt in self.commands_by_session().head(10).items():
            print(f'  {sid}  {cnt} commands')
        print()
        print(f'=== Top {top_n} commands ===')
        for cmd, cnt in self.top_commands(top_n).items():
            print(f'  {cnt:5d}  {cmd[:80]}')
        print()
        print('=== Longest sessions ===')
        for sid, dur in self.longest_sessions():
            print(f'  {sid}  {dur}')
        print()
        print(f'=== Suspicious sessions: {len(self.suspicious_sessions())} ===')


if __name__ == '__main__':
    import sys
    from log_loader import CowrieLogLoader
    log_path = sys.argv[1] if len(sys.argv) > 1 else \
               '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    df = CowrieLogLoader(log_path).load_json()
    SessionAnalyzer(df).full_report()
