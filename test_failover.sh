#!/usr/bin/env bash
# Teste de tolerancia a falhas do agente:
#   servidor no ar por 5 s -> cai por 4 s -> volta; o agente roda 20 s sem parar.
# Esperado: o agente avisa da queda, guarda eventos em buffer, reconecta sozinho
# e descarrega o buffer. Compara eventos entregues pelo agente x recebidos
# pelas duas instancias do servidor.
cd "$(dirname "$0")"
make -s
PORT=9494
TMP=$(mktemp -d)

./server -p $PORT -w 2 -o /dev/null > "$TMP/s1.txt" 2>&1 & S1=$!
sleep 1
./agent -p $PORT -n resil -m normal -r 100 -t 20 > "$TMP/ag.txt" 2> "$TMP/ag.err" & AG=$!

sleep 5
echo ">> derrubando o servidor (SIGINT)"
kill -INT $S1; wait $S1
sleep 4
echo ">> servidor de volta"
./server -p $PORT -w 2 -o /dev/null > "$TMP/s2.txt" 2>&1 & S2=$!

wait $AG
sleep 1
kill -INT $S2; wait $S2

echo; echo "=== eventos do agente (stderr) ==="; cat "$TMP/ag.err"
echo "=== resumo do agente ===";   cat "$TMP/ag.txt"
R1=$(grep RESUMO "$TMP/s1.txt" | sed -E 's/.*recebidos=([0-9]+).*/\1/')
R2=$(grep RESUMO "$TMP/s2.txt" | sed -E 's/.*recebidos=([0-9]+).*/\1/')
SENT=$(sed -E 's/.*enviados=([0-9]+).*/\1/' "$TMP/ag.txt")
echo "=== conferencia ==="
echo "entregues pelo agente : $SENT"
echo "recebidos servidor #1 : $R1"
echo "recebidos servidor #2 : $R2"
echo "perdidos              : $((SENT - R1 - R2))"
rm -rf "$TMP"
