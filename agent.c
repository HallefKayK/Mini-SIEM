/*
 * agent.c - Agente do Mini-SIEM: simula um servidor que gera eventos de login
 * e os envia por TCP (sockets) ao servidor central.
 *
 * Linha enviada:  agente|ip|evento|usuario\n
 *
 * Tolerancia a falhas:
 *   - Todo evento entra primeiro num buffer circular local (BUF_CAP linhas).
 *   - Se a conexao cair (ou o servidor ainda nao estiver no ar), o agente
 *     continua gerando eventos no buffer e tenta reconectar com backoff
 *     exponencial (500 ms, 1 s, 2 s, 4 s, ate 8 s).
 *   - Ao reconectar, descarrega o buffer em ordem. Se o buffer encher, o
 *     evento mais antigo e descartado (e contado).
 *   - Semantica de entrega: melhor esforco. Eventos ja entregues ao kernel
 *     mas ainda nao lidos pelo servidor no instante da queda podem se perder
 *     (sem ACK de aplicacao); um evento reenviado apos erro pode duplicar.
 *
 * Modos:
 *   normal : trafego legitimo (IPs aleatorios, ~3% de falhas)
 *   attack : um IP atacante tenta varias senhas e, no fim, consegue entrar
 *   mixed  : trafego normal com rajadas de ataque de tempos em tempos
 *
 * Uso: ./agent [-H host] [-p porta] [-n nome] [-m modo] [-r eventos/s] [-t segundos]
 *      -r 0 = o mais rapido possivel (util para benchmark)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BUF_CAP            10000
#define LINE_SZ            160
#define CONNECT_TIMEOUT_MS 2000
#define BACKOFF_MIN_MS     500
#define BACKOFF_MAX_MS     8000
#define DRAIN_GRACE_MS     10000

static const char *USERS[]    = { "alice", "bob", "carol", "dave", "erin" };
static const char *ATTACK_U[] = { "root", "admin", "ubuntu", "test", "oracle", "postgres" };
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* ------------------------------------------------------------- estado */

typedef struct {
    char s[LINE_SZ];
    int  len;
} line_t;

static line_t pending[BUF_CAP];              /* buffer circular de eventos */
static int    p_head, p_count;

static unsigned long long generated, delivered, dropped;
static int                reconnects;

static const char *g_host = "127.0.0.1", *g_port = "9090", *g_name = "agent01";
static int         g_fd = -1, ever_connected;
static long        backoff_ms, next_retry_ms;
static unsigned    seed;

/* --------------------------------------------------------------- rede */

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* connect() com timeout, para nao travar quando o host esta fora do ar */
static int connect_to(const char *host, const char *port, int timeout_ms)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res, *p;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, timeout_ms) == 1) {
                int err = 0;
                socklen_t el = sizeof err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                rc = err ? -1 : 0;
            } else {
                rc = -1;
            }
        }
        if (rc == 0) {
            fcntl(fd, F_SETFL, flags);          /* volta ao modo bloqueante */
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd, const char *buf, int len)
{
    int off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, (size_t)(len - off), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        off += (int)n;
    }
    return 0;
}

/* Backoff exponencial: 500 ms, 1 s, 2 s, 4 s, 8 s, 8 s, ... */
static void schedule_retry(void)
{
    if (backoff_ms == 0)
        backoff_ms = BACKOFF_MIN_MS;
    else
        backoff_ms = backoff_ms * 2 > BACKOFF_MAX_MS ? BACKOFF_MAX_MS : backoff_ms * 2;
    next_retry_ms = now_ms() + backoff_ms;
}

/* Tenta (re)conectar se preciso e descarrega o buffer em ordem. */
static void pump(void)
{
    if (g_fd < 0) {
        if (now_ms() < next_retry_ms)
            return;
        g_fd = connect_to(g_host, g_port, CONNECT_TIMEOUT_MS);
        if (g_fd < 0) {
            schedule_retry();
            fprintf(stderr, "[%s] servidor indisponivel; nova tentativa em %ld ms "
                            "(pendentes=%d)\n", g_name, backoff_ms, p_count);
            return;
        }
        if (ever_connected) {
            reconnects++;
            fprintf(stderr, "[%s] reconectado; descarregando %d eventos pendentes\n",
                    g_name, p_count);
        }
        ever_connected = 1;
        backoff_ms = 0;
    }

    while (p_count > 0) {
        line_t *l = &pending[p_head];
        if (send_all(g_fd, l->s, l->len) != 0) {
            fprintf(stderr, "[%s] conexao perdida (pendentes=%d); reconectando...\n",
                    g_name, p_count);
            close(g_fd);
            g_fd = -1;
            backoff_ms = 0;
            schedule_retry();
            return;
        }
        p_head = (p_head + 1) % BUF_CAP;
        p_count--;
        delivered++;
    }
}

/* ------------------------------------------------------------ eventos */

static void enqueue(const char *ip, const char *evt, const char *user)
{
    if (p_count == BUF_CAP) {                 /* buffer cheio: descarta o mais antigo */
        p_head = (p_head + 1) % BUF_CAP;
        p_count--;
        dropped++;
    }
    line_t *l = &pending[(p_head + p_count) % BUF_CAP];
    l->len = snprintf(l->s, LINE_SZ, "%s|%s|%s|%s\n", g_name, ip, evt, user);
    if (l->len >= LINE_SZ) {                  /* nome/usuario gigante: trunca */
        l->len = LINE_SZ - 1;
        l->s[l->len - 1] = '\n';
    }
    p_count++;
    generated++;
    pump();
}

static void random_ip(char *out, size_t sz)
{
    snprintf(out, sz, "10.0.%d.%d", (int)(rand_r(&seed) % 250) + 1,
             (int)(rand_r(&seed) % 250) + 1);
}

static void normal_event(void)
{
    char ip[32];
    random_ip(ip, sizeof ip);
    const char *evt = (rand_r(&seed) % 100 < 3) ? "LOGIN_FAIL" : "LOGIN_OK";
    enqueue(ip, evt, USERS[rand_r(&seed) % N(USERS)]);
}

static void attack_fail(const char *ip)
{
    enqueue(ip, "LOGIN_FAIL", ATTACK_U[rand_r(&seed) % N(ATTACK_U)]);
}

/* --------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    const char *mode = "normal";
    int rate = 20, duration = 10, opt;

    while ((opt = getopt(argc, argv, "H:p:n:m:r:t:")) != -1) {
        switch (opt) {
        case 'H': g_host = optarg; break;
        case 'p': g_port = optarg; break;
        case 'n': g_name = optarg; break;
        case 'm': mode = optarg; break;
        case 'r': rate = atoi(optarg); break;
        case 't': duration = atoi(optarg); break;
        default:
            fprintf(stderr, "Uso: %s [-H host] [-p porta] [-n nome] "
                            "[-m normal|attack|mixed] [-r ev/s] [-t seg]\n", argv[0]);
            return 1;
        }
    }
    if (strcmp(mode, "normal") && strcmp(mode, "attack") && strcmp(mode, "mixed")) {
        fprintf(stderr, "modo invalido: %s\n", mode);
        return 1;
    }

    seed = (unsigned)time(NULL) ^ (unsigned)getpid();
    signal(SIGPIPE, SIG_IGN);

    char attacker[32];
    snprintf(attacker, sizeof attacker, "203.0.113.%d", (int)(getpid() % 200) + 1);

    long interval_ns = rate > 0 ? 1000000000L / rate : 0;
    struct timespec nap = { 0, interval_ns };
    long t0 = now_ms();

    pump();                                   /* primeira tentativa de conexao */

    while (now_ms() - t0 < (long)duration * 1000L) {
        if (!strcmp(mode, "attack")) {
            attack_fail(attacker);
        } else if (!strcmp(mode, "mixed")) {
            normal_event();
            if (generated % 100 == 0)         /* rajada de 8 falhas */
                for (int i = 0; i < 8; i++)
                    attack_fail(attacker);
        } else {
            normal_event();
        }
        if (interval_ns > 0)
            nanosleep(&nap, NULL);
    }

    if (!strcmp(mode, "attack"))              /* atacante acerta a senha */
        enqueue(attacker, "LOGIN_OK", "admin");

    /* periodo de graca: tenta esvaziar o buffer antes de sair */
    long deadline = now_ms() + DRAIN_GRACE_MS;
    while (p_count > 0 && now_ms() < deadline) {
        pump();
        if (p_count > 0)
            usleep(100000);
    }
    if (g_fd >= 0)
        close(g_fd);

    printf("[%s] modo=%s enviados=%llu descartados=%llu reconexoes=%d pendentes=%d\n",
           g_name, mode, delivered, dropped, reconnects, p_count);
    return 0;
}
