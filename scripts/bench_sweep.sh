#!/bin/bash
# Cost of the flow-expiry sweep: same trace, sweep period 1 s / 10 s / never.
# usage: bench_sweep.sh MAWI_PCAP [reps]
BIN=${BIN:-./build/nanodpi}
for S in 1000 10000 0; do
  echo "== sweep every ${S} ms of trace time (0 = never)"
  "$BIN" -F 2097152 -S "$S" -b "${2:-5}" "$1" | grep -E '^bench|^flows'
done
