#!/usr/bin/env python3
"""
timeline_builder.py — Forensic session timeline with millisecond deltas.
Supports single session, IP, top-N, and family modes.
"""
import json, sys, argparse, csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

LOG_PATH   = Path('home/cowrie/cowrie/var/log/cowrie/cowrie.json')
CSV_PATH   = Path('classified_sessions.csv')

# ── Event label mapping ───────────────────────────────────────────────────────
LABELS = {
    'cowrie.session.connect':       'CONNECT',
    'cowrie.client.version':        'VERSION',
    'cowrie.client.kex':            'HASSH',
    'cowrie.login.failed':          'FAIL',
    'cowrie.login.success':         'SUCCESS',
    'cowrie.command.input':         'CMD',
    'cowrie.command.failed':        'CMD-FAIL',
    'cowrie.session.file_download': 'DOWNLOAD',
    'cowrie.session.file_upload':   'UPLOAD',
    'cowrie.direct-tcpip.request':  'TUNNEL',
    'cowrie.session.closed':        'CLOSE',
}

def load_sessions(log_path: Path) -> dict:
    """Load all events grouped by session ID."""
    sessions = defaultdict(list)
    with log_path.open('r', errors='ignore') as f:
        for line in f:
            try: e = json.loads(line)
            except: continue
            sid = e.get('session')
            if sid: sessions[sid].append(e)
    # Sort each session by timestamp
    for sid in sessions:
        sessions[sid].sort(key=lambda x: x.get('timestamp', ''))
    return sessions

def parse_ts(ts_str: str):
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        return None

def render_event(e: dict) -> str:
    """Format a single event into a readable one-liner."""
    eid   = e.get('eventid', '')
    label = LABELS.get(eid, eid.split('.')[-1].upper()[:10])
    parts = [f'[{label:<8}]']

    if eid in ('cowrie.login.failed', 'cowrie.login.success'):
        parts.append(f'{e.get("username","")}:{e.get("password","")}')
    elif eid == 'cowrie.command.input':
        parts.append(e.get('input', '')[:80])
    elif eid == 'cowrie.command.failed':
        parts.append(e.get('input', '')[:60] + ' [not found]')
    elif eid == 'cowrie.session.file_download':
        parts.append(f'url={e.get("url","")} sha={e.get("shasum","")[:12]}...')
    elif eid == 'cowrie.session.file_upload':
        parts.append(f'file={e.get("filename","")} sha={e.get("shasum","")[:12]}...')
    elif eid == 'cowrie.client.version':
        parts.append(e.get('version', '')[:60])
    elif eid == 'cowrie.client.kex':
        parts.append(f'hassh={e.get("hassh","")[:16]}')
    elif eid == 'cowrie.direct-tcpip.request':
        parts.append(f'{e.get("dst_ip","")}:{e.get("dst_port","")}')
    elif eid == 'cowrie.session.closed':
        parts.append(f'duration={e.get("duration","")}s')

    return ' '.join(parts)

def print_timeline(session_id: str, events: list, tsv_writer=None):
    """Print or write forensic timeline for one session."""
    if not events: return
    src_ip = next((e.get('src_ip') for e in events if e.get('src_ip')), 'unknown')
    print(f'\n{"="*70}')
    print(f'SESSION  {session_id}')
    print(f'IP       {src_ip}')
    print(f'EVENTS   {len(events)}')
    print(f'{"="*70}')

    t0 = parse_ts(events[0].get('timestamp', ''))
    t_prev = t0

    for e in events:
        ts = parse_ts(e.get('timestamp', ''))
        if ts and t0:
            abs_ms  = int((ts - t0).total_seconds() * 1000)
            delta_ms= int((ts - t_prev).total_seconds() * 1000) if t_prev else 0
            ts_str  = f'+{abs_ms:7d}ms  (+{delta_ms:6d}ms)'
        else:
            ts_str = ' ' * 24
        t_prev = ts

        line = render_event(e)
        print(f'  {ts_str}  {line}')
        if tsv_writer:
            tsv_writer.writerow([session_id, src_ip,
                                  e.get('timestamp',''), abs_ms if ts else '',
                                  e.get('eventid',''), line])

def load_family_sessions(csv_path: Path, family: str) -> list:
    """Load session IDs for a given family from classified_sessions.csv."""
    ids = []
    if not csv_path.exists():
        print(f'[!] {csv_path} not found. Run classify_cowrie.py first.', file=sys.stderr)
        return ids
    with csv_path.open('r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('family','').lower() == family.lower():
                ids.append(row['session'])
    return ids

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description='Cowrie forensic timeline builder')
group  = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--session', help='Single session ID')
group.add_argument('--ip',      help='All sessions from source IP')
group.add_argument('--top',     type=int, help='Top N sessions by command count')
group.add_argument('--family',  help='Sessions by family (from classify_cowrie.py)')
parser.add_argument('--log',    default=str(LOG_PATH), help='Path to cowrie.json')
parser.add_argument('--tsv',    help='Write TSV output to this file')
args = parser.parse_args()

sessions = load_sessions(Path(args.log))
print(f'[+] Loaded {len(sessions)} sessions')

# Determine which sessions to show
target_ids = []
if args.session:
    target_ids = [args.session]
elif args.ip:
    target_ids = [sid for sid, evs in sessions.items()
                  if any(e.get('src_ip') == args.ip for e in evs)]
elif args.top:
    cmd_counts = {
        sid: sum(1 for e in evs if e.get('eventid') == 'cowrie.command.input')
        for sid, evs in sessions.items()
    }
    target_ids = [s for s, _ in sorted(cmd_counts.items(),
                  key=lambda x: -x[1])[:args.top]]
elif args.family:
    target_ids = load_family_sessions(CSV_PATH, args.family)

print(f'[+] Showing {len(target_ids)} session(s)')

tsv_fh = open(args.tsv, 'w', newline='') if args.tsv else None
tsv_w  = None
if tsv_fh:
    tsv_w = csv.writer(tsv_fh, delimiter='\t')
    tsv_w.writerow(['session_id','src_ip','timestamp','abs_ms','eventid','detail'])

for sid in target_ids:
    print_timeline(sid, sessions.get(sid, []), tsv_w)

if tsv_fh:
    tsv_fh.close()
    print(f'\n[+] TSV saved: {args.tsv}')
