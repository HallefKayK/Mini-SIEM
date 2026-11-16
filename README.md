# Mini-SIEM Distribuído

Sistema cliente x servidor para **detecção de ataques de força bruta em tempo real**,
feito em C com **Sockets (TCP)** e **Pthreads**.
Atividade Prática de Sistemas Distribuídos.

## O problema

Um servidor sozinho, olhando seus próprios logs, não enxerga ataques distribuídos
e é um ponto único de falha. Em um SIEM, **agentes** espalhados pela rede enviam
eventos de login a um **servidor central**, que correlaciona tudo em tempo real e
dispara alertas.

## Arquitetura

```
 agent (web01) ─┐
 agent (db01)  ─┼── TCP ──► [accept loop] ──► 1 thread por agente (produtor)
 agent (vpn01) ─┘                                      │  linhas "agente|ip|evento|usuario"
                                                       ▼
                                      fila limitada (4096) — mutex + 2 condvars
                                                       │
                                                       ▼
                                           pool de N workers (consumidores)
                                                       │
                                                       ▼
                       tabela hash por IP (1024 buckets, 1 mutex por bucket)
                                                       │
                                                       ▼
                                  alertas → stdout + alerts.log (mutex próprio)
```

Decisões de concorrência (ótimas para o relatório):

| Decisão | Por quê |
|---|---|
| Fila limitada com `mutex` + `cond_wait` | Produtor/consumidor clássico; a fila cheia gera *backpressure* (o agente desacelera em vez de perder evento) |
| Um mutex **por bucket** (lock striping) | Workers só disputam lock se processarem IPs do mesmo bucket; um mutex global serializaria tudo |
| I/O de alerta **fora** da seção crítica | Evita segurar o lock do bucket enquanto escreve em disco |
| Contadores com `stdatomic` | Estatísticas sem lock |
| Encerramento limpo (SIGINT) | `g_stop` + `broadcast` com o lock da fila travado, evitando perda de sinal; workers drenam a fila antes de sair |
| Cada worker escreve só no próprio `last_ns` | Mede a janela real sem criar contenção |

### Protocolo

Texto, uma linha por evento: `agente|ip|evento|usuario\n`, com `evento` = `LOGIN_FAIL` ou `LOGIN_OK`.

### Regras de detecção

1. **BRUTE_FORCE**: 5 falhas do mesmo IP em até 10 s (com cooldown de 30 s por IP).
2. **POSSIBLE_COMPROMISE**: `LOGIN_OK` logo após uma rajada de falhas do mesmo IP.

Parâmetros no topo de `server.c` (`FAIL_THRESHOLD`, `FAIL_WINDOW_SEC`, `ALERT_COOLDOWN`).

### Tolerância a falhas do agente (alta disponibilidade)

O servidor central é o ponto sensível, então o **agente** foi feito para sobreviver à queda dele:

- Todo evento entra primeiro num **buffer circular local** (10.000 linhas).
- Se a conexão cair, ou o servidor ainda não estiver no ar, o agente **continua gerando eventos** no buffer e tenta **reconectar com backoff exponencial** (0,5 s → 1 s → 2 s → 4 s → 8 s). O `connect()` tem timeout de 2 s, então um servidor fora do ar não trava o agente.
- Ao reconectar, **descarrega o buffer em ordem**. Se o buffer encher, descarta o evento mais antigo e conta em `descartados`.
- **Semântica de entrega: melhor esforço.** Não há ACK de aplicação, então um evento já entregue ao kernel, mas ainda não lido pelo servidor no instante da queda, pode se perder; um evento reenviado após erro pode duplicar.

Resultado medido em `./test_failover.sh` (servidor cai por 4 s durante 20 s de execução): 747 eventos acumulados e descarregados após a reconexão, 0 descartados, 1 perdido em 1.980 (o que estava em trânsito).

### Mapeamento para os modelos de programação paralela (Aula 10)

O professor listou: Threads, Memória compartilhada, Passagem de mensagem, Paralelismo de dados e Modelos híbridos. Modelo principal declarado: **Threads (Pthreads)**.

| Modelo | No Mini-SIEM |
|---|---|
| **Threads** (principal) | Thread por agente, pool de workers, fila produtor/consumidor com `mutex` e `cond_wait` |
| Memória compartilhada | Tabela hash por IP compartilhada entre os workers (1 mutex por bucket) |
| Passagem de mensagem | Agentes e servidor trocam mensagens por sockets TCP, sem memória compartilhada entre máquinas |
| Híbrido | Passagem de mensagem entre os nós + threads com memória compartilhada dentro do servidor |

Termos da disciplina para usar no relatório: *granularidade* (razão computação/comunicação: o `-c` do benchmark controla isso) e *speedup observado* (vazão com N workers ÷ vazão com 1 worker).

## Como usar

```bash
make                 # compila server e agent
./run_demo.sh        # demo: 1 servidor + 4 agentes (2 normais, 1 misto, 1 atacante)
./test_failover.sh   # derruba o servidor por 4 s e mostra o agente reconectando
make tsan            # gera server_tsan com ThreadSanitizer (checagem de data races)
./bench.sh 200 5 "1 2 4 8"   # benchmark: vazão x nº de workers (custo 200 µs/evento)
```

Manualmente, em terminais diferentes (ou em máquinas diferentes na mesma rede):

```bash
./server -p 9090 -w 4 -o alerts.log
./agent -H 127.0.0.1 -p 9090 -n web01 -m normal -r 50 -t 30
./agent -H 127.0.0.1 -p 9090 -n vpn01 -m attack -r 10 -t 15
```

Opções do servidor: `-p porta`, `-w workers`, `-o arquivo`, `-c custo_us` (custo simulado
por evento, para benchmark), `-i segundos` (intervalo das estatísticas).
Opções do agente: `-H host`, `-p porta`, `-n nome`, `-m normal|attack|mixed`,
`-r eventos/s` (0 = máximo), `-t segundos`.

Testado: demo sem perda de eventos (recebidos = processados), **0 avisos do ThreadSanitizer** e reconexão do agente após queda do servidor (`test_failover.sh`).

## Testes para o relatório

1. **Corretude**: `run_demo.sh` deve gerar 2 × `BRUTE_FORCE` e 1 × `POSSIBLE_COMPROMISE`; tráfego normal não deve gerar alerta.
2. **Escalabilidade**: `./bench.sh 200 5 "1 2 4 8"` na sua máquina e faça um gráfico workers × vazão. O ganho só aparece com vários núcleos; discuta onde o ganho satura (nº de núcleos, lock da fila).
3. **Backpressure**: rode com `-w 1 -c 500` e agentes em `-r 0`; observe a fila em 4096 e nenhuma perda de eventos.
4. **Data races**: `make tsan` e rode a demo com `server_tsan`.
5. **Tolerância a falhas**: `./test_failover.sh` e relate eventos acumulados, descartados e perdidos. Discuta a semântica de melhor esforço.
6. **Multi-máquina** (se possível): servidor em um PC, agentes em outro (`-H IP_DO_SERVIDOR`). Vale muito na demo, por ser distribuído de verdade.

## Limitações (seção honesta do relatório)

- A tabela de IPs não tem expiração (cresce indefinidamente).
- Sem TLS/autenticação dos agentes.
- Carimbo de tempo é do servidor (não confia no relógio do agente).
- Servidor único: continua sendo um ponto único de falha; o agente tolera a queda, mas os alertas ficam parados até ele voltar.
- Sem ACK de aplicação: entrega em melhor esforço (pode perder 1 evento em trânsito na queda, ou duplicar um reenviado).
- O buffer do agente é só em memória: se o próprio agente reiniciar, perde o que estava pendente.

## Extensões opcionais (a reconexão do agente já está pronta)

- **Regra de password spraying**: mesmo IP tentando muitos usuários diferentes.
- **Agente real**: ler `/var/log/auth.log` (estilo `tail -f`) e converter para o protocolo.
- **Expiração de entradas** da tabela (thread de limpeza).
- **Servidor de reserva**: o agente tenta um segundo servidor se o primeiro cair (failover de verdade).
- **ACK de aplicação**: o servidor confirma cada lote e o agente só remove do buffer o que foi confirmado (entrega "pelo menos uma vez").

## Cronograma sugerido (2 semanas)

**Semana 1 — base e validação**
- Dias 1–2: ler e entender o código, rodar a demo, desenhar o diagrama da arquitetura.
- Dias 3–4: ajustar regras e parâmetros; testes de corretude; `make tsan`.
- Dias 5–7: benchmark em máquina multi-núcleo; coletar números e gráficos.

**Semana 2 — extensão e relatório**
- Dias 8–10: estudar a lógica de reconexão (`pump()` em `agent.c`) até conseguir explicá-la sem olhar; opcionalmente 1 extensão (ACK ou servidor de reserva).
- Dias 11–12: teste multi-máquina e ensaio da demonstração.
- Dias 13–14: relatório final e revisão.

## Roteiro do relatório

1. Introdução e problema (por que um servidor único não basta)
2. Arquitetura e tecnologias (Sockets, Pthreads)
3. Decisões de concorrência (tabela acima)
4. Implementação (protocolo, regras de detecção)
5. Testes e resultados (corretude, escalabilidade, TSan)
6. Limitações e trabalhos futuros
7. Conclusão
