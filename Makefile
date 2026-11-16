CC     ?= gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -pthread

all: server agent

server: server.c
	$(CC) $(CFLAGS) -o $@ $<

agent: agent.c
	$(CC) $(CFLAGS) -o $@ $<

# Versao com ThreadSanitizer: detecta data races (bom para citar no relatorio)
tsan: server.c agent.c
	$(CC) -g -O1 -std=gnu11 -pthread -fsanitize=thread -o server_tsan server.c
	$(CC) $(CFLAGS) -o agent agent.c

clean:
	rm -f server agent server_tsan alerts.log

.PHONY: all tsan clean
