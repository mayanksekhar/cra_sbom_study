#!/usr/bin/env bash
# One project per process, memory capped. Usage: CAP=5G bash harness/run_reach_product.sh [project ...]
cd "$(dirname "$0")/.." || exit 1
export PATH="$PATH:$HOME/go/bin"
export GOMEMLIMIT="${GOMEMLIMIT:-4GiB}"
CAP="${CAP:-5G}"
PROJECTS="${*:-fzf blackbox_exporter nats-server alertmanager restic caddy cli hugo helm k9s}"
for p in $PROJECTS; do
  if [ -f "results_go/reach_product/$p.json" ]; then echo "$(date +%H:%M:%S) skip $p (done)"; continue; fi
  echo "$(date +%H:%M:%S) start $p (cap $CAP, free $(free -m | awk '/Mem:/{print $7}') MB available)"
  T=""; [ -x /usr/bin/time ] && T="/usr/bin/time -f %M -o /tmp/peak_$p.txt"
  $T systemd-run --user --scope -q -p MemoryMax="$CAP" -p MemorySwapMax=0 python3 harness/reach_product.py run "$p"
  rc=$?
  peak=""; [ -f /tmp/peak_$p.txt ] && peak=" peak $(( $(tail -n1 /tmp/peak_$p.txt) / 1024 )) MB"
  echo "$(date +%H:%M:%S) end   $p exit $rc$peak"
done
echo "$(date +%H:%M:%S) all requested projects attempted"
