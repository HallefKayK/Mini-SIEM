#!/usr/bin/env bash
# Benchmark: vazao do servidor variando o numero de workers.
# Cada evento tem um custo extra simulado (-c, em microsegundos) para que o
# processamento, e nao a rede, seja o gargalo.
# Os agentes enviam o mais rapido possivel (-r 0); o script espera o servidor
# processar TUDO que foi enviado e le a vazao medida pelo proprio servidor
# (do primeiro evento recebido ao ultimo processado).
# Uso: ./bench.sh [custo_us] [duracao_s] [lista_de_workers]
set -e
cd "$(dirname "$0")"
make -s
COST=${1:-200}
T=${2:-5}
WORKERS=${3:-"1 2 4 8"}
PORT=9292
TMP=$(mktemp -d)

echo "workers;processados;janela_s;vazao_ev_s"
for W in $WORKERS; do
    ./server -p $PORT -w "$W" -c "$COST" -i 1 -o /dev/null > "$TMP/srv.txt" 2>&1 &
    SRV=$!
    sleep 1
    PIDS=()
    for i in 1 2 3 4; do
        ./agent -p $PORT -n bench$i -m normal -r 0 -t "$T" > "$TMP/ag$i.txt" & PIDS+=($!)
    done
    for p in "${PIDS[@]}"; do wait "$p"; done

    SENT=$(cat "$TMP"/ag*.txt | sed -E 's/.*enviados=([0-9]+).*/\1/' | paste -sd+ | bc)
    for _ in $(seq 1 300); do                     # espera drenar (max 5 min)
        DONE=$(grep '^\[stats\]' "$TMP/srv.txt" | tail -1 | sed -E 's/.*processados=([0-9]+).*/\1/')
        [ "${DONE:-0}" -ge "$SENT" ] && break
        sleep 1
    done

    kill -INT $SRV; wait $SRV || true
    LINE=$(grep RESUMO "$TMP/srv.txt")
    PROC=$(echo "$LINE" | sed -E 's/.*processados=([0-9]+).*/\1/')
    WIN=$(echo "$LINE"  | sed -E 's/.*janela=([0-9.]+)s.*/\1/')
    VAZ=$(echo "$LINE"  | sed -E 's/.*vazao=([0-9]+) ev\/s.*/\1/')
    echo "$W;$PROC;$WIN;$VAZ"
done
rm -rf "$TMP"
