"""For each TLS flow in the given pcaps: ClientHello size, first-segment size,
offset of the SNI extension, and whether the key share carries X25519MLKEM768 (0x11ec)."""
import os
import struct
import sys
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, rdpcap

base = os.path.expanduser("~/dpi-data/nDPI/tests/cfgs/default/pcap/")
for fn in sys.argv[1:]:
    segs = defaultdict(list)
    for p in rdpcap(base + fn):
        if TCP not in p or p[TCP].dport != 443 or not bytes(p[TCP].payload):
            continue
        ip = p[IP] if IP in p else p[IPv6]
        segs[(ip.src, p[TCP].sport)].append((p[TCP].seq, bytes(p[TCP].payload)))
    for k, s in segs.items():
        s.sort()
        first_len = len(s[0][1])
        stream = b"".join(x for _, x in s)[:8192]
        if len(stream) < 9 or stream[0] != 0x16 or stream[5] != 1:
            continue
        ch_len = struct.unpack(">I", b"\0" + stream[6:9])[0] + 4
        o = 9 + 2 + 32
        o += 1 + stream[o]
        o += 2 + struct.unpack(">H", stream[o:o + 2])[0]
        o += 1 + stream[o]
        end = o + 2 + struct.unpack(">H", stream[o:o + 2])[0]
        o += 2
        sni_off, mlkem, order = None, False, []
        while o + 4 <= end and o + 4 <= len(stream):
            t, l = struct.unpack(">HH", stream[o:o + 4])
            order.append(t)
            if t == 0:
                sni_off = o                     # offset within the TCP stream
            if t == 0x33 and b"\x11\xec\x04\xc0" in stream[o + 4:o + 4 + l]:
                mlkem = True
            o += 4 + l
        print(f"{fn:55s} {k[1]:5d} CH={ch_len:5d}B seg1={first_len:5d}B sni_at={sni_off} "
              f"mlkem={mlkem} sni_in_seg1={sni_off is not None and sni_off + 9 < first_len} "
              f"keyshare_before_sni={order.index(0x33) < order.index(0) if 0 in order and 0x33 in order else None}")
