#!/bin/bash
# A/B for the hot/cold split of the expiry sweep, interleaved to cancel drift.
#   old : sweep reads each 256-byte flow struct (last_ns, state)   [rebuilt from a patched copy]
#   new : sweep reads the 4-byte deadline[] array
#   none: no sweep at all (lower bound)
# usage: ab_sweep.sh MAWI_PCAP [rounds]
set -eu
MAWI=$1; ROUNDS=${2:-5}
SRC=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
cp -r "$SRC"/src "$SRC"/include "$SRC"/tools "$SRC"/Makefile "$TMP"/
mkdir -p "$TMP/tests" "$TMP/bench" && cp "$SRC"/tests/*.c "$TMP/tests/" && cp "$SRC"/bench/*.c "$TMP/bench/"
python3 - "$TMP/src/flow.c" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
old_touch = s[s.index("void ftab_touch("):s.index("uint32_t ftab_expire(")]
s = s.replace(old_touch, "void ftab_touch(ftab_t *t, const flow_t *f) { (void)t; (void)f; }\n\n")
s = s.replace("""            if (!dl[i] || dl[i] > now_s) break;      /* empty or not due: struct never touched */
            flow_t *f = &t->slots[i];""", """            flow_t *f = &t->slots[i];
            (void)dl;
            if (!f->used) break;
            uint32_t to = f->k.proto == 6 ? t->timeout_s[f->state] : t->udp_timeout_s;
            if (now_ns < f->last_ns || now_ns - f->last_ns <= (uint64_t)to * 1000000000ull) break;""")
s = s.replace("    t->deadline[i] = 0;\n    t->slots[i].used = 0;", "    t->slots[i].used = 0;")
open(p, "w").write(s)
EOF
make -C "$TMP" -j4 build/nanodpi > /dev/null
make -C "$SRC" -j4 build/nanodpi > /dev/null
echo "# $(lscpu | sed -n 's/Model name: *//p'); best-of-3 per run, $ROUNDS interleaved rounds"
for r in $(seq "$ROUNDS"); do
  for v in old new none; do
    case $v in
      old)  out=$("$TMP/build/nanodpi" -F 2097152 -S 1000 -b 3 "$MAWI" | grep '^bench') ;;
      new)  out=$("$SRC/build/nanodpi" -F 2097152 -S 1000 -b 3 "$MAWI" | grep '^bench') ;;
      none) out=$("$SRC/build/nanodpi" -F 2097152 -S 0 -b 3 "$MAWI" | grep '^bench') ;;
    esac
    best=$(echo "$out" | sed 's/.*best_s=\([0-9.]*\).*/\1/')
    pk=$(echo "$out" | sed 's/.*packets=\([0-9]*\).*/\1/')
    echo "round=$r variant=$v best_ns_per_pkt=$(python3 -c "print(round($best*1e9/$pk,1))")"
  done
done
rm -rf "$TMP"
