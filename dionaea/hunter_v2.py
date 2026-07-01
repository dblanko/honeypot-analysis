#!/usr/bin/env python3
import argparse, json, math, os
from collections import defaultdict
from itertools import combinations

def load_hunter_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)

def build_clusters(samples, threshold=0.4):
    # samples: list of dicts (one family)
    # threshold: string similarity threshold
    n = len(samples)
    if n == 0:
        return []

    # similarity graph
    adj = {i: set() for i in range(n)}
    for (i, s1), (j, s2) in combinations(enumerate(samples), 2):
        sim = jaccard(s1.get("strings", []), s2.get("strings", []))
        if sim >= threshold:
            adj[i].add(j)
            adj[j].add(i)

    # search for connected components
    visited = set()
    clusters = []
    for i in range(n):
        if i in visited:
            continue
        stack = [i]
        comp = []
        visited.add(i)
        while stack:
            v = stack.pop()
            comp.append(v)
            for u in adj[v]:
                if u not in visited:
                    visited.add(u)
                    stack.append(u)
        clusters.append(comp)

    return clusters, adj

def build_graph(samples, adj):
    nodes = []
    edges = []

    for i, s in enumerate(samples):
        nodes.append({
            "id": i,
            "sha256": s["sha256"],
            "family": s.get("family", "Unknown"),
            "score": s.get("score", 0),
            "size": s.get("size", 0),
            "path": s.get("path", ""),
        })

    for i, neighbors in adj.items():
        for j in neighbors:
            if i < j:
                edges.append({
                    "source": i,
                    "target": j,
                })

    return {"nodes": nodes, "edges": edges}

def main():
    ap = argparse.ArgumentParser(
        description="hunter_v4: clustering and graph over hunter.json"
    )
    ap.add_argument("--json", default="hunter.json", help="Input hunter.json")
    ap.add_argument("--out-json", default="clusters.json", help="Output clusters JSON")
    ap.add_argument("--out-md", default="clusters.md", help="Output Markdown report")
    ap.add_argument("--similarity-threshold", type=float, default=0.4,
                    help="Jaccard threshold for clustering (default: 0.4)")
    ap.add_argument("--min-score", type=int, default=1,
                    help="Minimum score to include sample (default: 1)")
    args = ap.parse_args()

    samples = load_hunter_json(args.json)
    # filtering out noise
    samples = [s for s in samples if s.get("score", 0) >= args.min_score]

    # grouping by families
    families = defaultdict(list)
    for s in samples:
        fam = s.get("family", "Unknown")
        families[fam].append(s)

    all_clusters = {}
    all_graphs = {}

    md_lines = []
    md_lines.append(f"# Hunter v4 clusters report\n")
    md_lines.append(f"**Source:** `{args.json}`\n")
    md_lines.append(f"**Min score:** {args.min_score}\n")
    md_lines.append(f"**Similarity threshold:** {args.similarity_threshold}\n")
    md_lines.append("")

    for fam, fam_samples in families.items():
        md_lines.append(f"## Family: {fam}")
        md_lines.append(f"- Samples: {len(fam_samples)}\n")

        clusters, adj = build_clusters(fam_samples, threshold=args.similarity_threshold)
        all_clusters[fam] = [[fam_samples[i]["sha256"] for i in comp] for comp in clusters]
        all_graphs[fam] = build_graph(fam_samples, adj)

        md_lines.append(f"- Clusters: {len(clusters)}\n")

        for idx, comp in enumerate(clusters, 1):
            md_lines.append(f"### {fam} cluster #{idx}")
            md_lines.append("")
            md_lines.append("| SHA256 | Score | Size | Path |")
            md_lines.append("|--------|-------|------|------|")
            for i in comp:
                s = fam_samples[i]
                md_lines.append(
                    f"| `{s['sha256']}` | {s.get('score', 0)} | {s.get('size', 0)} | `{s.get('path', '')}` |"
                )
            md_lines.append("")

        md_lines.append("---\n")

    out = {
        "clusters": all_clusters,
        "graphs": all_graphs,
    }

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"[+] Families: {len(families)}")
    print(f"[+] Clusters JSON saved to {args.out_json}")
    print(f"[+] Markdown saved to {args.out_md}")

if __name__ == "__main__":
    main()
