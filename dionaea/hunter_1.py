#!/usr/bin/env python3
import argparse, os, hashlib, json, math
from datetime import datetime

MAX_READ = 256 * 1024   # We read only the first 256 KB

IOC_PATTERNS = {
    "url":      [b"http://", b"https://"],
    "exe":      [b".exe"],
    "dll":      [b".dll"],
    "wannacry": [b"mssecsvr", b"tasksche", b"launcher.dll", b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff"],
    "crypto":   [b"xmrig", b"stratum", b"minerd", b"pool"],
    "smb":      [b"SMB", b"MS17-010", b"EternalBlue"],
    "linuxbot": [b"wget ", b"curl ", b"busybox"],
}

def fast_strings(data, min_len=6):
    out, buf = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode("utf-8", "ignore"))
            buf = bytearray()
    if len(buf) >= min_len:
        out.append(buf.decode("utf-8", "ignore"))
    return out

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            ent -= p * math.log2(p)
    return round(ent, 3)

def get_pe_timestamp(data):
    if data[:2] != b"MZ":
        return None
    try:
        import struct
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        timestamp = struct.unpack("<I", data[e_lfanew+8:e_lfanew+12])[0]
        return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return None

def detect_iocs(data):
    hits = []
    for name, patterns in IOC_PATTERNS.items():
        for p in patterns:
            if p in data:
                hits.append(name)
                break
    return hits

def classify(info):
    s = " ".join(info.get("strings", [])).lower()
    iocs = info.get("iocs", [])

    if "wannacry" in iocs:
        return "WannaCry"
    if "crypto" in iocs:
        return "Cryptominer"
    if "linuxbot" in iocs:
        return "LinuxBot"
    if "url" in iocs and "exe" in iocs:
        return "Loader"
    if "dll" in iocs and ("virtualalloc" in s or "createremotethread" in s):
        return "RAT"
    return "Unknown"

def score(info):
    return len(info.get("iocs", []))

def analyze_file(path):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(MAX_READ)

        strings = fast_strings(head)
        iocs = detect_iocs(head)
        sha256 = compute_sha256(path)
        ent = entropy(head)
        timestamp = get_pe_timestamp(head)

        info = {
            "path": path,
            "filename": os.path.basename(path),
            "size": size,
            "sha256": sha256,
            "entropy": ent,
            "pe_timestamp": timestamp,
            "iocs": iocs,
            "strings": strings[:20],
        }

        info["family"] = classify(info)
        info["score"] = score(info)
        return info

    except Exception:
        return None

def walk(root):
    for dirpath, _, files in os.walk(root):
        for f in files:
            yield os.path.join(dirpath, f)

def generate_markdown(results, top_n):
    lines = []
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append(f"# Dionaea Hunter Report")
    lines.append("")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Total suspicious samples:** {len(results)}")
    lines.append("")

    lines.append(f"## Top {top_n} samples")
    lines.append("")
    lines.append("| Score | Family | SHA256 | Size | Timestamp |")
    lines.append("|-------|--------|--------|-------|-----------|")

    for r in results[:top_n]:
        lines.append(
            f"| {r['score']} | {r['family']} | `{r['sha256']}` | {r['size']} | {r['pe_timestamp']} |"
        )

    lines.append("\n---\n")

    for r in results[:top_n]:
        lines.append(f"## {r['filename']}")
        lines.append("")
        lines.append(f"- **Path:** `{r['path']}`")
        lines.append(f"- **SHA256:** `{r['sha256']}`")
        lines.append(f"- **Size:** {r['size']} bytes")
        lines.append(f"- **Entropy:** {r['entropy']}")
        lines.append(f"- **Timestamp:** {r['pe_timestamp']}")
        lines.append(f"- **Family:** {r['family']}")
        lines.append(f"- **IOCs:** {', '.join(r['iocs'])}")
        lines.append("")
        lines.append("### Strings")
        lines.append("```")
        for s in r["strings"]:
            lines.append(s)
        lines.append("```")
        lines.append("\n---\n")

    return "\n".join(lines)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-d", "--dir", default="/opt/dionaea-data/binaries")
    p.add_argument("--json", default="hunter.json")
    p.add_argument("--md", default="hunter.md")
    p.add_argument("--top", type=int, default=30)
    args = p.parse_args()

    results = []
    for path in walk(args.dir):
        info = analyze_file(path)
        if info and info["score"] > 0:
            results.append(info)

    results.sort(key=lambda x: x["score"], reverse=True)

    with open(args.json, "w") as f:
        json.dump(results, f, indent=2)

    md = generate_markdown(results, args.top)
    with open(args.md, "w") as f:
        f.write(md)

    print(f"[+] Done. Suspicious samples: {len(results)}")
    print(f"[+] JSON saved to {args.json}")
    print(f"[+] Markdown saved to {args.md}")
    print()
    print("Top suspicious:")
    for r in results[:args.top]:
        print(f"{r['score']:>2}  {r['family']:<10}  {r['sha256']}  {r['path']}")

if __name__ == "__main__":
    main()
