# nano-dpi

A small deep-packet-inspection engine and stateful firewall in C11.
It tracks flows and the TCP state machine, reassembles the first client flight,
names the application from the HTTP Host, TLS SNI, DNS query or the **SNI inside an
encrypted QUIC Initial**, maps names to apps/categories (including RPZ threat feeds),
applies first-match firewall rules (linear scan or tuple-space search) and polices
per subscriber with an RFC 2697 srTCM.

~2,300 lines of C (engine + CLI), one dependency (OpenSSL libcrypto, for QUIC's HKDF + AES-GCM).
Input is pcap/pcapng replay. **There is no DPDK or live-capture front end** - see
"Not built" below.

```
pcap/pcapng -> decode -> flow table + TCP state -> DPI (first client flight only)
            -> verdict cached on the flow -> srTCM policer -> allow / drop
```

## Results

All numbers from an i5-9300H laptop under WSL2 unless marked CI. Raw outputs in
[`results/local/`](results/local); CI re-runs everything except the MAWI trace.

**Hostname agreement with nDPI** - nDPI's own test corpus (683 captures, commit
`0bd6245`) with its committed expected output as the oracle; every flow where nDPI
extracted a hostname:

| L7 | flows | same host | agreement |
|---|---:|---:|---:|
| HTTP | 1,161 | 1,159 | 99.8% |
| TLS | 791 | 783 | 99.0% |
| DNS | 492 | 450 | 91.5% |
| QUIC | 167 | 137 | 82.0% |
| **all** | **2,611** | **2,529** | **96.9%** |

The misses are categorised in `results/local/ndpi_mismatches.csv`: 28 QUIC flows are
gQUIC (Google's pre-IETF protocol, not supported); 35 DNS names contain binary bytes
that nDPI and nano-dpi sanitise differently (20 of them from one fuzzed capture).
This is agreement with nDPI on nDPI's corpus, not accuracy on unseen traffic.

**Reassembly matters for post-quantum TLS.** Chrome 154 / Opera 135 ClientHellos carry
an X25519MLKEM768 key share (1,216 B) and are 1.7-1.9 KB, more than one 1,440-byte
segment. Chromium randomises extension order, and in 7 of 13 such hellos in the corpus
the SNI landed in segment 2. A per-packet parser misses those; with first-flight
reassembly nano-dpi gets them (16 flows over the corpus: 2,529 vs 2,513).
[`scripts/clienthello_split.py`](scripts/clienthello_split.py) shows it per flow.

**Throughput** - one core, packets preloaded in memory, whole pipeline:

| trace | packets | flows | ns/pkt | Mpps |
|---|---:|---:|---:|---:|
| MAWI backbone, 2025-01-01, first 400 MB (36.7 s, header-only) | 5.44 M | 716k created, 600k peak live | 345 | 2.9 |
| nDPI corpus, all 683 files (payload-heavy, DPI on every flow) | 137k | 10.3k | 901 | 1.1 |
| same corpus, CI runner (Xeon 6975P-C, `results/ci/`) | 137k | 10.3k | 413 | 2.4 |

MAWI payloads are stripped for anonymisation, so that row measures flow tracking, not DPI.

**The expiry sweep was the bottleneck on a big table.** Sweeping 2M slots of 256-byte
flow structs once per trace second cost more than the rest of the pipeline. A parallel
4-byte `deadline[]` array (hot/cold split) fixed it - interleaved A/B, 5 rounds:
499 -> 345 ns/pkt; sweep overhead +216 -> +62 ns/pkt ([`scripts/ab_sweep.sh`](scripts/ab_sweep.sh)).

**Rule classification** - linear vs tuple-space search, identical answers on every lookup
(0 mismatches in 14 M lookups):

| profile | rules | shapes | linear | TSS |
|---|---:|---:|---:|---:|
| ACL-like (specific prefixes, exact ports) | 1,001 | 13 | 971 ns | 184 ns |
| | 10,001 | 13 | 9,831 ns | 207 ns |
| | 30,001 | 13 | 38,192 ns | 264 ns |
| broad (catch-alls early in the list) | 10,001 | 510 | 691 ns | 3,950 ns |

TSS wins once the match is deep (crossover ~200 rules); with broad rules near the top
a contiguous linear scan finds a match first. Either way the engine evaluates rules only
at flow creation and once after app identification: 0.08 evaluations per packet on the
corpus.

**Policer** (simulated time, Poisson arrivals, IMIX): passed rate within 0.01% of CIR
from 10 Mbit/s to 1 Gbit/s at 0.5x-10x offered load. At 1 Mbit/s with a 3 KB CBS and
load near CIR it passes 1.5-2.1% too little - a two-packet bucket turns Poisson clumps red.

**Robustness:** 71 unit checks (including the RFC 9001 and RFC 9369 QUIC key vectors);
ASan + UBSan over all 683 corpus captures, 0 errors; libFuzzer over the whole pipeline,
7.0 M inputs in 5 min, no crash.

## Bugs found by measuring

1. **Silent packet loss in the pcapng reader.** A fixed 16-entry interface table;
   `sites.pcapng` has 32 interfaces, so 477 of 1,100 packets were skipped and 22 TLS
   flows were "not found". Now 256 interfaces and a `skipped` counter.
2. **Expiry sweep cost** - above.
3. **Normalisation gaps vs nDPI**: Host header `:port` kept, WebDAV methods unknown,
   6in4/4in6 tunnels not decapsulated, PPP link type unsupported. Agreement went
   93.3% -> 96.9% after fixing these.

## Build and run

Linux, gcc or clang, `libssl-dev`.

```sh
make                     # build/nanodpi, tests, benches
make test                # unit tests
make asan                # ASan+UBSan build in build-asan/
make fuzz FUZZ_CC=clang  # libFuzzer target in build-fuzz/

./build/nanodpi -o flows.csv capture.pcapng
./build/nanodpi -C malware:urlhaus-filter.rpz -R rules/example.rules -o flows.csv *.pcap
./build/nanodpi -n ...   # no reassembly (per-packet parsing)
./build/nanodpi -b 10 -F 2097152 big.pcap   # benchmark, 10 in-memory passes

python3 scripts/compare_ndpi.py <nDPI>/tests/cfgs/default ./build/nanodpi out/
```

Rules syntax ([`rules/example.rules`](rules/example.rules)):

```
policer video-cap cir=2m cbs=64k ebs=128k
drop cat=malware
drop proto=tcp dport=23
police=video-cap app=youtube
```

## Layout

| file | what |
|---|---|
| `src/pcapio.c` | pcap + pcapng reader, no libpcap |
| `src/pkt.c` | L2-L4 decode: VLAN, PPPoE, SLL, IPv6 ext headers, IP-in-IP |
| `src/flow.c` | flow table (open addressing, backward-shift delete), TCP state machine, expiry |
| `src/reasm.c` | bitmap reassembly of the first client flight / QUIC CRYPTO stream |
| `src/dpi.c` | HTTP Host, TLS SNI, DNS qname parsers |
| `src/quic.c` | QUIC v1/v2/draft Initial: HKDF keys, header protection, AES-GCM, CRYPTO frames |
| `src/apps.c` | domain-suffix -> app / category, feed loader (lists, hosts, RPZ) |
| `src/rules.c` | first-match rules: linear + tuple-space search |
| `src/policer.c` | srTCM (RFC 2697), per-subscriber instances |
| `src/engine.c` | the per-packet pipeline |

Walkthrough with the interview questions: [`docs/NOTES.md`](docs/NOTES.md).

## Not built

- DPDK / AF_XDP / live capture. The engine takes `(bytes, len, timestamp)`, so a
  `rte_eth_rx_burst` loop in front of `engine_packet()` is the missing piece.
- Multi-core (would need a symmetric RSS hash so both directions hit one core).
- TCP sequence-window tracking, IP fragment reassembly, conntrack cross-check.
- gQUIC, HTTPS interception, traffic shaping (policing only), behavioural
  video/audio/chat classification, port-range rules, decision-tree classifiers.
