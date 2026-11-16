#!/usr/bin/env bash
# Demo: 1 servidor + 4 agentes (2 normais, 1 misto, 1 atacante)
set -e
cd "$(dirname "$0")"
make -s
rm -f alerts.log

./server -p 9090 -w 4 -o alerts.log &
SRV=$!
sleep 1

PIDS=()
./agent -n web01 -m normal -r 50 -t 15 & PIDS+=($!)
./agent -n web02 -m normal -r 50 -t 15 & PIDS+=($!)
./agent -n db01  -m mixed  -r 30 -t 15 & PIDS+=($!)
./agent -n vpn01 -m attack -r 10 -t 12 & PIDS+=($!)

for p in "${PIDS[@]}"; do wait "$p"; done
sleep 1
kill -INT "$SRV"
wait "$SRV" || true

echo
echo "=== alerts.log ==="
cat alerts.log
