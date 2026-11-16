# nano-dpi study notes

A one-to-two-day path through the code, in the order a packet travels.
Each section: what the code does, where it is, what an interviewer will ask.

---

## 0. The pipeline (engine.c, ~200 lines)

```
pcap/pcapng bytes
  -> pkt_parse        L2..L4 decode            (pkt.c)
  -> ftab_get         flow lookup / create     (flow.c)
  -> tcp_track        TCP state machine        (flow.c)
  -> inspect          DPI on first client flight only   (engine.c -> dpi.c, quic.c)
  -> classify         firewall rules, only on flow create + once after DPI  (rules.c)
  -> srtcm_color      per-subscriber policer   (policer.c)
  -> verdict ALLOW / DROP
```

Two design points to say out loud:

1. **DPI looks only at the first few client packets** (`DPI_MAX_PKTS = 10`). Once the
   hostname is known, the flow is "done" and every later packet costs one hash lookup.
   That is how real DPI engines hit line rate: inspection is front-loaded.
2. **The verdict is cached on the flow.** Rules run when the flow is created
   (L3/L4 fields) and once more when DPI names the app. On the nDPI corpus that is
   ~0.08 rule evaluations per packet. Per-packet cost barely depends on rule count.

---

## 1. Capture reading (pcapio.c)

- Whole file read into memory, `cap_next` hands out pointers - no copies, no I/O in the loop.
- Classic pcap: magic `a1b2c3d4` (µs) / `a1b23c4d` (ns), either byte order.
- pcapng: blocks. SHB (byte-order magic), IDB (per-interface link type and
  `if_tsresol`), EPB (packet with interface id), SPB, obsolete PB.
- **Bug found:** the interface table was fixed at 16. `sites.pcapng` has **32 IDBs**
  (a capture on many adapters), so packets on interfaces 16-31 were silently skipped:
  623 of 1,100 packets read, 22 TLS flows missing vs nDPI. Fix: 256 interfaces and a
  `skipped` counter so it can never be silent again.
  *Lesson: anything that drops packets must count them.*

## 2. Decode (pkt.c)

- Link types: Ethernet (+ VLAN/QinQ, PPPoE), Linux SLL/SLL2, raw IP, BSD loopback, PPP.
- IPv4: header length, total length (strip Ethernet padding), fragments
  (non-first fragment has no L4 header -> counted, not inspected; no IP reassembly).
- IPv6: walks extension headers (hop-by-hop, routing, dest-opts, fragment).
- **Tunnels:** IP-in-IP (proto 4 / 41 = 4in4, 6in4, 4in6) unwrapped once. Added because
  nDPI decapsulates them and the `6in4tunnel.pcap` flows were "not found".
- Never reads past `caplen`; the fuzzer + ASan corpus run back that up.

## 3. Flow table + TCP state (flow.c)

- **Key canonicalisation:** the lower `(addr, port)` endpoint is always `a`, so both
  directions hash to one slot. `client_is_a` remembers who opened the connection
  (SYN sender; for mid-stream pickups the side with the high port).
- **Open addressing, linear probing, backward-shift delete.** No tombstones: on delete,
  later entries in the probe chain move back if their home slot allows it.
  Table refuses new flows past 90% load and counts `table_full_drops` (fail-open).
- **TCP states** (RFC 9293 names, conntrack-style observer):
  `SYN_SENT -> SYN_RCVD -> ESTABLISHED -> FIN_WAIT -> LAST_ACK -> TIME_WAIT`, `CLOSE` on RST.
  Mid-stream pickup goes straight to ESTABLISHED with `midstream=1` (conntrack "loose").
  The final ACK must come from the side that sent the first FIN.
  A SYN on a TIME_WAIT/CLOSE flow = **port reuse**: old record is emitted, flow reset
  (`flows_reopened`, 211 in the MAWI slice).
- **Not done:** sequence-window tracking (conntrack checks seq/ack are in window;
  that is what stops a blind RST from killing a flow). Say so if asked.
- Timeouts: ESTABLISHED 300 s (conntrack uses 5 days - fine for a host, not for a
  box holding millions of flows), SYN 30 s, TIME_WAIT 120 s, UDP 30 s.

### The expiry-sweep finding (the best perf story)

Every 1 s of trace time the table is swept for idle flows. On the MAWI backbone slice
(5.4M packets, 600k live flows, 2M slots x 256 B = 512 MB) that sweep was **more than
half the per-packet cost**:

A/B, interleaved so laptop drift hits all variants equally (`scripts/ab_sweep.sh`,
5 rounds x best-of-3, median of the round-bests; `results/local/ab_sweep.txt`):

| variant (sweep every 1 s) | ns/pkt | Mpps |
|---|---:|---:|
| old: sweep reads each flow struct | 499 | 2.0 |
| new: sweep reads `deadline[]` | 345 | 2.9 |
| no sweep at all (floor) | 283 | 3.5 |

Old was slower than new in all 5 rounds. Sweep overhead: +216 ns -> +62 ns per packet.
(Absolute numbers on this laptop drift by +-30% between runs an hour apart - one
reason to only trust interleaved comparisons.)

Why: reading `last_ns` + `state` meant touching one cache line per slot - 2M lines,
~37 times. Fix: a parallel `uint32_t deadline[]` (second the flow expires, 0 = empty),
updated per packet, moved along with the flow on backward-shift. The sweep reads 8 MB
of deadlines and only touches a flow struct that is actually due.
Cost: deadlines are whole seconds (+1 s rounding), so flows expire up to ~1 s later
(128.8k vs 131.9k expired in the slice).
What a production box would do next: incremental sweep (a slice per tick, like
conntrack's gc worker) or a timer wheel.

## 4. Reassembly (reasm.c, 25 lines)

- Only the **first client flight** (up to 8 KB) - enough for a ClientHello or HTTP headers.
- Bytes written at their stream offset; a bitmap marks which offsets have arrived;
  `contig` = gap-free prefix the parsers may read. Out-of-order, retransmission and
  overlap all take the same path. Overlap policy: **first writer wins** (a real IPS must
  pick a policy to match the target OS, or attackers split payloads with conflicting
  overlaps - "TCP segment overlap evasion", Ptacek & Newsham 1998).
- TCP offset = `seq - isn` (uint32 wrap-around is correct). ISN from SYN+1, or the first
  payload seq when picked up mid-stream.
- The same buffer collects **QUIC CRYPTO frames** by their CRYPTO offset.

## 5. App identification (dpi.c)

Parser contract: given a prefix of the stream, return MATCH (host filled or ""),
NO, or NEED_MORE. Parse "as far as the bytes go" - so a ClientHello whose SNI is in
segment 1 is identified without waiting for segment 2.

- **HTTP:** method list (incl. WebDAV `PROPFIND` etc.), walk header lines, `Host:`
  case-insensitive, strip `:port` (but not from a bare IPv6 literal).
- **TLS:** record type 0x16, version 3.x, handshake type 1. Collects handshake bytes
  across records, then walks ClientHello: version, random(32), session_id, cipher
  suites, compression, extensions -> `server_name` (type 0).
  Malformed-but-complete messages return MATCH (TLS, no name), never NEED_MORE forever.
- **DNS:** port 53 (UDP either direction; TCP with 2-byte length prefix), first
  question name. Rejects compression pointers in the question.

### The reassembly finding (real, from real browser captures)

Modern browsers send **post-quantum key shares**: X25519MLKEM768 adds a 1,216-byte
key. ClientHellos in the corpus from Chrome 154 / Opera 135 are **1.7-1.9 KB**, and the
first segment carries 1,440 bytes. Chromium also **randomises extension order**, so in
**7 of 13** Chromium hellos `key_share` came before `server_name` and the SNI landed in
segment 2 (`scripts/clienthello_split.py` shows this per flow). A per-packet parser
misses exactly those; the reassembling one gets them. Safari keeps SNI early.

Over the whole corpus reassembly is worth 16 flows (2,529 vs 2,513 of 2,611): the 7
TLS above, HTTP headers split across packets, DNS-over-TCP length prefix in its own
segment. Small today, growing as PQ TLS becomes default.

## 6. QUIC Initial decryption (quic.c, ~200 lines) - the "most people don't know" part

QUIC encrypts even the first packet, but the key is derived from public data:

```
initial_secret = HKDF-Extract(salt_for_version, client_DCID)
client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
key = Expand-Label(client_secret, "quic key", 16)   # "quicv2 key" for v2
iv  = Expand-Label(client_secret, "quic iv", 12)
hp  = Expand-Label(client_secret, "quic hp", 16)
```

Steps per client Initial:
1. Parse long header: flags, version, DCID, SCID, token (varint), length (varint).
2. **Header protection:** sample = 16 bytes starting at `pn_offset + 4`;
   `mask = AES-ECB(hp, sample)`; `flags ^= mask[0] & 0x0f` -> packet-number length;
   packet number bytes ^= `mask[1..]`.
3. nonce = iv XOR packet number; AAD = the unprotected header;
   **AES-128-GCM** decrypt. The tag check proves the keys/version were right.
4. Walk frames (PADDING, PING, ACK, CRYPTO); CRYPTO data goes into the reassembly
   buffer at its offset - Chrome splits the ClientHello across CRYPTO frames *and*
   across Initial packets, often out of order.
5. Run the TLS handshake parser on the buffer -> SNI.

Gotchas: keys come from the client's **first** DCID; later client Initials carry the
server-chosen DCID but keep the original keys. Each version has its own salt
(v1, v2 RFC 9369, drafts 23-28, 29-34, mvfst). Unit tests check the RFC 9001 A.1 and
RFC 9369 A.1 key vectors.

Not supported: **gQUIC** (Google's pre-IETF Q0xx, plaintext CHLO) - these are the 28
QUIC flows where nDPI has a name and we do not.

## 7. Categories (apps.c)

Suffix lookup from most to least specific (`rr3---sn.googlevideo.com`,
`googlevideo.com`, `com`) in one hash set. Built-in app table (YouTube, Netflix, ...)
plus feeds loaded as categories: plain lists, hosts files, or **RPZ zones** - the same
URLhaus feed nano-dns uses (1,985 domains).

## 8. Rules: linear vs tuple-space search (rules.c)

Fields: client prefix, server prefix, proto, client port, server port, app, category.
Each exact or "any". First match wins.

**Tuple-space search** (Srinivasan, Suri, Varghese 1999): group rules by *shape*
(prefix lengths + which fields are "any"). One hash table per shape, keyed by the masked
fields. Lookup = one probe per shape; shapes are visited in order of their best rule and
the search stops when no remaining shape can beat the current match.
Linear and TSS are checked to agree on every lookup in the benchmark (0 mismatches).

Results (i5-9300H laptop, WSL2):

| profile | rules | shapes | linear ns | TSS ns |
|---|---:|---:|---:|---:|
| acl | 1,001 | 13 | 971 | 184 |
| acl | 10,001 | 13 | 9,831 | 207 |
| acl | 30,001 | 13 | 38,192 | 264 |
| broad | 10,001 | 510 | 691 | 3,950 |

The interesting part is the **broad** row: with near-catch-all rules early in the list,
a linear scan finds a match after a few hundred contiguous, prefetch-friendly rules
(~1-2 ns each), while TSS still pays a hash + likely cache miss for each of hundreds of
shapes. TSS wins when shapes are few and the match is deep - real ACLs.
Not done: port ranges (TSS needs range-to-prefix expansion), decision trees
(HiCuts/HyperCuts), the JD's "40-50 attributes" (7 here).

## 9. Policer (policer.c)

srTCM, RFC 2697, colour-blind. Two buckets at CIR: C (CBS) then E (EBS).
GREEN if C has B bytes, else YELLOW if E has, else RED (dropped).
Tokens stored as **bytes x 1e9** so refill is `cir_Bps * elapsed_ns` in integers; elapsed
is clamped to "time to fill both buckets" so the multiply can't overflow.
One instance per (policer, subscriber IP).

Accuracy (Poisson arrivals, IMIX sizes, 30 simulated s): passed rate within 0.01% of
CIR at 10 Mbit/s-1 Gbit/s. At **1 Mbit/s with CBS = 3 KB** and load 0.9-1.1x CIR it
passes 1.5-2.1% less than it should - 3 KB is two full-size packets, so Poisson
clumping goes red below CIR. Burst size, not rate, is what you tune near the limit.
Not done: shaping (queue + delay instead of drop).

---

## What was measured, and against what

- **nDPI agreement:** 683 captures from nDPI's own test suite (commit 0bd6245), its
  committed expected outputs as the oracle. 2,611 flows where nDPI extracted a
  HTTP/TLS/DNS/QUIC hostname: **96.9% same host** (HTTP 99.8, TLS 99.0, DNS 91.5,
  QUIC 82.0). Misses are categorised in `results/local/ndpi_mismatches.csv`:
  gQUIC (28), DNS names with binary bytes that nDPI and I sanitise differently (35,
  20 from one fuzzed capture), nDPI heuristics (mid-stream TLS, server-side names).
  This is agreement with nDPI on nDPI's corpus - not accuracy on unseen traffic.
- **Throughput:** single core, packets preloaded into memory, no NIC.
  MAWI is header-only (anonymised), so it measures flow tracking, not DPI.
- **Robustness:** unit tests (incl. RFC key vectors), ASan+UBSan over every corpus
  capture, libFuzzer on the whole pipeline.

## What this is not (say it before they ask)

- **No DPDK / no live capture.** The engine takes `(bytes, len, timestamp)`; pcap
  replay drives it. In bypass-lab the DPDK path ran on the af_packet PMD in CI.
  Wiring `rte_eth_rx_burst` in front of `engine_packet` is the obvious next step.
- No conntrack cross-check (needs root + replay into netfilter), no TCP window tracking.
- No HTTPS interception, no traffic shaping, no video/audio/chat heuristics, no gQUIC.
- Single-threaded. A multi-core version would RSS-hash on the canonical 5-tuple
  (symmetric hash!) so both directions of a flow land on one core - no locks.
