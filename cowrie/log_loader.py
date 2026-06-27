#!/usr/bin/env python3
"""
log_loader.py — Core Cowrie log loader.
Used by all other analysis scripts as the data ingestion layer.
"""
import json
import pandas as pd
from pathlib import Path


class CowrieLogLoader:
    """
    Generic loader for Cowrie JSON logs.
    Works with cowrie.json (bare-metal and Docker).
    Returns a DataFrame with all events.
    """

    def __init__(self, log_path):
        self.log_path = Path(log_path)
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

    def load_json(self):
        """
        Load cowrie.json line by line.
        Each line is a separate JSON event.
        Returns a DataFrame.
        """
        events = []
        with self.log_path.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError:
                    continue
        df = pd.DataFrame(events)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df

    @staticmethod
    def group_by_session(df):
        """Group events by session ID. Returns dict {session_id: DataFrame}."""
        if 'session' not in df.columns:
            return {}
        sessions = {}
        for session_id, group in df.groupby('session'):
            sessions[session_id] = group.sort_values('timestamp')
        return sessions

    @staticmethod
    def filter_events(df, eventid):
        """Return only rows matching a specific eventid."""
        return df[df['eventid'] == eventid].copy()

    @staticmethod
    def extract_credentials(df):
        """
        Extract login events (both failed and successful).
        Returns DataFrame with columns: timestamp, src_ip, username, password, success, session.
        """
        login_events = df[df['eventid'].isin([
            'cowrie.login.failed',
            'cowrie.login.success'
        ])]
        if login_events.empty:
            return pd.DataFrame()
        login_events = login_events.copy()
        login_events['success'] = login_events['eventid'] == 'cowrie.login.success'
        return login_events[['timestamp', 'src_ip', 'username', 'password', 'success', 'session']]\
               .sort_values('timestamp')


# ── Quick test ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    log_path = sys.argv[1] if len(sys.argv) > 1 else \
               '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    loader = CowrieLogLoader(log_path)
    df = loader.load_json()
    print(f'Total events:  {len(df)}')
    print(f'Event types:   {df["eventid"].nunique()}')
    print(f'Sessions:      {df["session"].nunique()}')
    creds = loader.extract_credentials(df)
    print(f'Login attempts:{len(creds)}')
    print(f'Successful:    {creds["success"].sum()}')
