#!/bin/bash
# Single-core, in-memory throughput of the whole pipeline (decode -> flow ->
# TCP state -> DPI -> verdict). Packets are loaded first; only the engine loop
# is timed. Usage: bench_throughput.sh NDPI_PCAP_DIR MAWI_PCAP OUT_FILE
set -u
BIN=${BIN:-./build/nanodpi}
NDPI=$1; MAWI=$2; OUT=$3
{
echo "# host: $(lscpu | sed -n 's/Model name: *//p'), $(nproc) vCPU, $(uname -r)"
echo "== nDPI corpus, all files, reassembly on"
"$BIN" -b 10 "$NDPI"/* 2>/dev/null | grep -E '^bench|^packets|^l7'
echo "== nDPI corpus, reassembly off"
"$BIN" -n -b 10 "$NDPI"/* 2>/dev/null | grep -E '^bench'
if [ -f "$MAWI" ]; then
  for S in 1000 10000 0; do
    echo "== MAWI head, 2M slots, sweep every ${S} ms of trace time (0 = never)"
    "$BIN" -F 2097152 -S $S -b 5 "$MAWI" | grep -E '^bench|^flows'
  done
fi
} | tee "$OUT"
