#!/usr/bin/env python3
"""
classify_cowrie.py — Three-layer Cowrie session classifier.
  Layer 1: HASSH fingerprint rules
  Layer 2: Command regex patterns
  Layer 3: TF-IDF + KMeans for unmatched sessions
"""
import json, re, sys
import pandas as pd
from pathlib import Path
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

LOG_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else \
           Path('/home/cowrie/cowrie/var/log/cowrie/cowrie.json')

# ── Layer 1: HASSH rules ─────────────────────────────────────────────────────
HASSH_RULES = {
    '03a80b21': ('mdrfckr',     'High',   'libssh_0.11.1 SSH backdoor'),
    '16443846': ('Go-scanner',  'High',   'SSH-2.0-Go crypto-targeting scanner'),
    '015322ee': ('Mozi',        'Medium', 'libssh_0.11.3 / AsyncSSH Mozi bot'),
    'a7a87fbe': ('Gafgyt',      'High',   'Gafgyt DDoS bot loader'),
    '92674c43': ('Generic-bot', 'Low',    'Common brute-force client'),
}

# ── Layer 2: Command regex rules ─────────────────────────────────────────────
COMMAND_RULES = [
    (r'mdrfckr',                          'mdrfckr',    'High',   'mdrfckr SSH key injection'),
    (r'\.ssh.*authorized_keys',           'mdrfckr',    'High',   'SSH authorized_keys manipulation'),
    (r'chattr\s+-ia\s+\.ssh',           'mdrfckr',    'High',   'chattr immutable flag removal'),
    (r'\bp\.txt\b|\br\.txt\b',       'Gafgyt',     'High',   'Gafgyt p.txt/r.txt dropper'),
    (r'23\.160\.56\.192|195\.20\.19\.212', 'Gafgyt', 'High','Gafgyt C2 server'),
    (r'\\x6[Ff]\\x6[Bb]',             'Mirai',      'High',   'Mirai hex-escaped liveness check'),
    (r'windyloveyou|windy\.arm|windy\.mips', 'Windy',  'High',  'Windy Mirai dropper'),
    (r'165\.22\.58\.103',               'Windy',      'High',   'Windy C2 server'),
    (r'/proc/1/mounts.*curl2.*ps.*sh',     'Mozi',       'High',   'Mozi deep recon payload'),
    (r'nicehash\.com|xmrig|c3pool',       'XMRig',      'High',   'XMRig cryptocurrency miner'),
    (r'redtail|rsa-key-20230629',          'RedTail',    'High',   'RedTail operator key'),
    (r'(wget|curl).*/tmp/',                'Downloader', 'Medium', 'Generic payload downloader'),
    (r'history\s+-c|/dev/null.*bash_history','AntiForen','Low',   'Log clearing attempt'),
    (r'uname.*proc.*uptime',               'Recon',      'Low',    'System recon payload'),
]

# ── Load logs ────────────────────────────────────────────────────────────────
sessions = defaultdict(lambda: {'hassh': None, 'commands': [], 'src_ip': None})

with LOG_PATH.open('r', errors='ignore') as f:
    for line in f:
        try: e = json.loads(line)
        except: continue
        sid = e.get('session')
        if not sid: continue
        if e.get('eventid') == 'cowrie.client.kex':
            sessions[sid]['hassh'] = e.get('hassh', '')[:8]
        if e.get('eventid') == 'cowrie.command.input':
            sessions[sid]['commands'].append(e.get('input', ''))
        if not sessions[sid]['src_ip']:
            sessions[sid]['src_ip'] = e.get('src_ip')

print(f'[+] Sessions loaded: {len(sessions)}')

# ── Classify ─────────────────────────────────────────────────────────────────
results = []
unmatched_ids = []

for sid, data in sessions.items():
    family, confidence, note = 'Unknown', 'Low', ''
    cmds_joined = ' '.join(data['commands'])

    # Layer 1
    h = data['hassh']
    if h and h in HASSH_RULES:
        family, confidence, note = HASSH_RULES[h]
    else:
        # Layer 2
        for pattern, fam, conf, n in COMMAND_RULES:
            if re.search(pattern, cmds_joined, re.IGNORECASE):
                family, confidence, note = fam, conf, n
                break

    if family == 'Unknown':
        unmatched_ids.append(sid)

    results.append({
        'session':    sid,
        'src_ip':     data['src_ip'],
        'hassh':      data['hassh'],
        'family':     family,
        'confidence': confidence,
        'note':       note,
        'cmd_count':  len(data['commands']),
        'commands':   cmds_joined[:200],
    })

# ── Layer 3: TF-IDF + KMeans ─────────────────────────────────────────────────
if unmatched_ids:
    unmatched_cmds = [
        ' '.join(sessions[sid]['commands']) or 'empty'
        for sid in unmatched_ids
    ]
    n_clusters = min(6, len(unmatched_ids))
    vec = TfidfVectorizer(max_features=200, min_df=1)
    X   = vec.fit_transform(unmatched_cmds)
    km  = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(X)

    # Write cluster keywords
    terms = vec.get_feature_names_out()
    with open('cluster_keywords.txt', 'w') as f:
        for ci in range(n_clusters):
            top = km.cluster_centers_[ci].argsort()[-10:][::-1]
            kws = ', '.join(terms[j] for j in top)
            f.write(f'Cluster {ci}: {kws}\n')

    # Update results
    label_map = {sid: f'Cluster-{labels[i]}' for i, sid in enumerate(unmatched_ids)}
    for r in results:
        if r['family'] == 'Unknown' and r['session'] in label_map:
            r['family']     = label_map[r['session']]
            r['confidence'] = 'ML'

# ── Save ─────────────────────────────────────────────────────────────────────
df = pd.DataFrame(results)
df.to_csv('classified_sessions.csv', index=False)

print(f'[+] Classified: {len(df)} sessions')
print(df['family'].value_counts().to_string())
print('[+] Output: classified_sessions.csv')
if unmatched_ids:
    print('[+] ML clusters: cluster_keywords.txt')
