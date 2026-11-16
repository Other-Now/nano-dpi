#!/usr/bin/env python3
"""Compare nanodpi's hostnames with nDPI's expected output on nDPI's own test corpus.

nDPI ships ~680 capture files with committed expected results
(tests/cfgs/default/result/<pcap>.out). Every flow line there has the
5-tuple, the protocol nDPI decided on, and "Hostname/SNI" when it extracted one.
We run nanodpi on the same capture and, for every flow nDPI labels HTTP / TLS /
DNS / QUIC *with* a hostname, check what we extracted for that 5-tuple.

usage: compare_ndpi.py NDPI_TESTS_DIR NANODPI_BIN OUT_DIR
"""
import collections
import csv
import os
import re
import subprocess
import sys
import tempfile

L7 = ("HTTP", "TLS", "DNS", "QUIC")
LINE = re.compile(r"^\s*\d+\s+(TCP|UDP)\s+(\S+)\s+(?:<->|->)\s+(\S+)\s")
PROTO = re.compile(r"\[proto: [\d.]+/([^\]]+)\]")
HOST = re.compile(r"\[Hostname/SNI: ([^\]]*)\]")


def norm(h):
    h = h.strip().lower().rstrip(".")
    return h


def key(proto, a, b):
    return (proto,) + tuple(sorted((a, b)))


def ndpi_flows(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            p = PROTO.search(line)
            h = HOST.search(line)
            name = p.group(1) if p else "Unknown"
            master = name.split(".")[0]
            out.append((key(m.group(1), m.group(2), m.group(3)), master, norm(h.group(1)) if h else ""))
    return out


def run(nanodpi, pcap, extra):
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as t:
        tmp = t.name
    r = subprocess.run([nanodpi, "-o", tmp] + extra + [pcap], capture_output=True, text=True, timeout=120)
    flows = collections.defaultdict(list)
    if r.returncode == 0:
        with open(tmp) as f:
            for row in csv.DictReader(f):
                flows[key(row["proto"], row["client"], row["server"])].append(row)
    os.unlink(tmp)
    return r.returncode, flows


def main():
    tests, nanodpi, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    pdir, rdir = os.path.join(tests, "pcap"), os.path.join(tests, "result")
    files = sorted(f for f in os.listdir(pdir) if os.path.exists(os.path.join(rdir, f + ".out")))
    modes = {"reasm": [], "no_reasm": ["-n"]}
    # tally[mode][l7] = Counter(outcome)
    tally = {m: collections.defaultdict(collections.Counter) for m in modes}
    l7_agree = {m: collections.Counter() for m in modes}
    crashes = []
    mism = []
    per_flow = collections.defaultdict(dict)   # (file, key) -> mode -> details
    pcaps_with_labels = 0
    for fn in files:
        nd = ndpi_flows(os.path.join(rdir, fn + ".out"))
        labelled = [(k, m, h) for k, m, h in nd if m in L7 and h]
        for mode, extra in modes.items():
            rc, ours = run(nanodpi, os.path.join(pdir, fn), extra)
            if rc != 0:
                crashes.append((fn, mode, rc))
                continue
            for k, master, host in labelled:
                rows = ours.get(k)
                if not rows:
                    outcome = "flow_not_found"
                else:
                    hosts = {norm(r["host"]) for r in rows}
                    l7s = {r["l7"] for r in rows}
                    l7_agree[mode]["same_l7" if master in l7s else "other_l7"] += 1
                    if host in hosts:
                        outcome = "same_host"
                    elif hosts - {""}:
                        outcome = "different_host"
                    else:
                        outcome = "no_host"
                per_flow[(fn, k)][mode] = (outcome, master, host,
                                           max(int(r["dpi_pkts"]) for r in rows) if rows else 0)
                if mode == "reasm" and outcome != "same_host":
                    got = "|".join(sorted({r["host"] for r in rows})) if rows else ""
                    mism.append((fn, master, " ".join(k), host, got, outcome))
                tally[mode][master][outcome] += 1
        if labelled:
            pcaps_with_labels += 1

    outcomes = ["same_host", "different_host", "no_host", "flow_not_found"]
    lines = [f"# nanodpi vs nDPI expected output\n",
             f"capture files with an nDPI .out: {len(files)}; with >=1 labelled HTTP/TLS/DNS/QUIC flow: {pcaps_with_labels}\n",
             f"nanodpi non-zero exits: {len(crashes)}\n"]
    for mode in modes:
        lines.append(f"\n## mode: {mode}\n\n| L7 | nDPI flows with host | " + " | ".join(outcomes) + " | agreement |\n")
        lines.append("|---|---:|" + "---:|" * len(outcomes) + "---:|\n")
        tot = collections.Counter()
        for l7 in L7:
            c = tally[mode][l7]
            n = sum(c.values())
            tot.update(c)
            lines.append(f"| {l7} | {n} | " + " | ".join(str(c[o]) for o in outcomes) +
                         f" | {100.0 * c['same_host'] / n if n else 0:.1f}% |\n")
        n = sum(tot.values())
        lines.append(f"| all | {n} | " + " | ".join(str(tot[o]) for o in outcomes) +
                     f" | {100.0 * tot['same_host'] / n:.1f}% |\n")
        lines.append(f"\nL7 label agreement on flows found: {dict(l7_agree[mode])}\n")
    with open(os.path.join(outdir, "ndpi_compare.md"), "w") as f:
        f.writelines(lines)
    with open(os.path.join(outdir, "ndpi_mismatches.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pcap", "ndpi_l7", "flow", "ndpi_host", "nanodpi_host", "outcome"])
        w.writerows(mism)
    wins = [(fn, " ".join(k), v["reasm"][1], v["reasm"][2], v["reasm"][3], v["no_reasm"][0])
            for (fn, k), v in per_flow.items()
            if v.get("reasm", ("",))[0] == "same_host" and v.get("no_reasm", ("",))[0] != "same_host"]
    with open(os.path.join(outdir, "reasm_only_wins.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pcap", "flow", "ndpi_l7", "host", "dpi_pkts_with_reasm", "no_reasm_outcome"])
        w.writerows(sorted(wins))
    with open(os.path.join(outdir, "ndpi_compare.md"), "a") as f:
        f.write(f"\nflows where only the reassembling engine got the name: {len(wins)} (reasm_only_wins.csv)\n")
    print("reasm-only wins:", len(wins))
    if crashes:
        print("crashes:", crashes)
    sys.stdout.writelines(lines)


if __name__ == "__main__":
    main()
