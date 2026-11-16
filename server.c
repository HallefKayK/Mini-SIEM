/*
 * server.c - Mini-SIEM distribuido: servidor central de analise de logs.
 *
 * Arquitetura (produtor/consumidor):
 *
 *   agentes --TCP--> [thread por cliente] --> fila limitada --> [pool de workers]
 *                      (produtores)           (mutex + condvar)   (consumidores)
 *                                                                      |
 *                                          tabela hash por IP <--------+
 *                                          (um mutex por bucket)
 *
 * Protocolo (texto, uma linha por evento):   agente|ip|evento|usuario\n
 *   evento: LOGIN_FAIL ou LOGIN_OK
 *
 * Regras de deteccao:
 *   1) BRUTE_FORCE : FAIL_THRESHOLD falhas do mesmo IP em ate FAIL_WINDOW_SEC s
 *   2) POSSIBLE_COMPROMISE : LOGIN_OK logo depois de uma rajada de falhas
 *
 * Uso: ./server [-p porta] [-w workers] [-o arquivo_alertas] [-c custo_us]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT     9090
#define DEFAULT_WORKERS  4
#define QUEUE_CAP        4096
#define N_BUCKETS        1024
#define FAIL_THRESHOLD   5     /* falhas para disparar alerta        */
#define FAIL_WINDOW_SEC  10    /* janela de tempo da deteccao        */
#define ALERT_COOLDOWN   30    /* segundos entre alertas do mesmo IP */
#define RECV_BUF         4096
#define STATS_INTERVAL   5

typedef struct {
    char   agent[32];
    char   ip[46];
    char   event[16];
    char   user[32];
    time_t ts;            /* carimbo de tempo do servidor (recebimento) */
} event_t;

/* ---------------------------------------------------------------- estado */

static atomic_int       g_stop;
static atomic_ullong    events_received, events_processed, alerts_total, parse_errors;
static atomic_int       clients_active;
static int              g_workers = DEFAULT_WORKERS;
static int              g_work_us = 0;      /* custo extra simulado (benchmark) */
static int              g_stats_interval = STATS_INTERVAL;
static atomic_llong     first_event_ns;     /* 0 ate o primeiro evento chegar   */
static long long       *worker_last_ns;     /* ultimo instante de cada worker   */
static FILE            *alert_fp  = NULL;
static pthread_mutex_t  alert_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------- fila limitada (monitor) --- */

typedef struct {
    event_t         buf[QUEUE_CAP];
    int             head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty, not_full;
} event_queue_t;

static event_queue_t q = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .not_empty = PTHREAD_COND_INITIALIZER,
    .not_full = PTHREAD_COND_INITIALIZER,
};

/* Produtor: bloqueia se a fila estiver cheia (backpressure). -1 = encerrando */
static int queue_push(const event_t *ev)
{
    pthread_mutex_lock(&q.lock);
    while (q.count == QUEUE_CAP && !atomic_load(&g_stop))
        pthread_cond_wait(&q.not_full, &q.lock);
    if (atomic_load(&g_stop)) {
        pthread_mutex_unlock(&q.lock);
        return -1;
    }
    q.buf[q.tail] = *ev;
    q.tail = (q.tail + 1) % QUEUE_CAP;
    q.count++;
    pthread_cond_signal(&q.not_empty);
    pthread_mutex_unlock(&q.lock);
    return 0;
}

/* Consumidor: bloqueia se vazia. -1 = encerrando e fila ja esvaziada */
static int queue_pop(event_t *ev)
{
    pthread_mutex_lock(&q.lock);
    while (q.count == 0 && !atomic_load(&g_stop))
        pthread_cond_wait(&q.not_empty, &q.lock);
    if (q.count == 0) {
        pthread_mutex_unlock(&q.lock);
        return -1;
    }
    *ev = q.buf[q.head];
    q.head = (q.head + 1) % QUEUE_CAP;
    q.count--;
    pthread_cond_signal(&q.not_full);
    pthread_mutex_unlock(&q.lock);
    return 0;
}

static int queue_depth(void)
{
    pthread_mutex_lock(&q.lock);
    int n = q.count;
    pthread_mutex_unlock(&q.lock);
    return n;
}

/* -------------------------- tabela hash por IP (um mutex por bucket) --- */

typedef struct ip_entry {
    char             ip[46];
    time_t           fails[FAIL_THRESHOLD];  /* buffer circular das ultimas falhas */
    int              nfails;                 /* quantas posicoes estao validas    */
    int              pos;                    /* proxima posicao de escrita        */
    time_t           last_alert;
    struct ip_entry *next;
} ip_entry_t;

typedef struct {
    pthread_mutex_t lock;
    ip_entry_t     *head;
} bucket_t;

static bucket_t table[N_BUCKETS];

static unsigned hash_ip(const char *s)           /* djb2 */
{
    unsigned h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h;
}

/* Chamar com o mutex do bucket travado. */
static ip_entry_t *find_entry(bucket_t *b, const char *ip, int create)
{
    for (ip_entry_t *e = b->head; e; e = e->next)
        if (strcmp(e->ip, ip) == 0)
            return e;
    if (!create)
        return NULL;
    ip_entry_t *e = calloc(1, sizeof *e);
    if (!e)
        return NULL;
    snprintf(e->ip, sizeof e->ip, "%s", ip);
    e->next = b->head;
    b->head = e;
    return e;
}

/* ---------------------------------------------------------------- alertas */

static void emit_alert(const char *kind, const event_t *ev, int count)
{
    char hhmmss[16];
    struct tm tmv;
    localtime_r(&ev->ts, &tmv);
    strftime(hhmmss, sizeof hhmmss, "%H:%M:%S", &tmv);

    pthread_mutex_lock(&alert_lock);
    printf("[%s] ALERTA %-20s ip=%-15s falhas=%d agente=%s usuario=%s\n",
           hhmmss, kind, ev->ip, count, ev->agent, ev->user);
    fflush(stdout);
    if (alert_fp) {
        fprintf(alert_fp, "%s;%s;%s;%d;%s;%s\n",
                hhmmss, kind, ev->ip, count, ev->agent, ev->user);
        fflush(alert_fp);
    }
    pthread_mutex_unlock(&alert_lock);
    atomic_fetch_add(&alerts_total, 1);
}

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void busy_wait_us(int us)
{
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) * 1000000L +
             (t.tv_nsec - t0.tv_nsec) / 1000 < us);
}

/* ------------------------------------------------------------- deteccao */

static void process_event(const event_t *ev)
{
    const char *alert_kind = NULL;
    int alert_count = 0;

    if (g_work_us > 0)
        busy_wait_us(g_work_us);

    bucket_t *b = &table[hash_ip(ev->ip) % N_BUCKETS];
    pthread_mutex_lock(&b->lock);

    if (strcmp(ev->event, "LOGIN_FAIL") == 0) {
        ip_entry_t *e = find_entry(b, ev->ip, 1);
        if (e) {
            e->fails[e->pos] = ev->ts;
            e->pos = (e->pos + 1) % FAIL_THRESHOLD;
            if (e->nfails < FAIL_THRESHOLD)
                e->nfails++;
            if (e->nfails == FAIL_THRESHOLD) {
                /* buffer cheio: e->pos aponta para a falha mais antiga */
                time_t oldest = e->fails[e->pos];
                if (ev->ts - oldest <= FAIL_WINDOW_SEC &&
                    ev->ts - e->last_alert >= ALERT_COOLDOWN) {
                    e->last_alert = ev->ts;
                    alert_kind = "BRUTE_FORCE";
                    alert_count = e->nfails;
                }
            }
        }
    } else if (strcmp(ev->event, "LOGIN_OK") == 0) {
        ip_entry_t *e = find_entry(b, ev->ip, 0);
        if (e && e->nfails == FAIL_THRESHOLD) {
            time_t newest = e->fails[(e->pos + FAIL_THRESHOLD - 1) % FAIL_THRESHOLD];
            if (ev->ts - newest <= FAIL_WINDOW_SEC) {
                alert_kind = "POSSIBLE_COMPROMISE";
                alert_count = e->nfails;
            }
        }
        if (e) {                      /* login valido zera o historico */
            e->nfails = 0;
            e->pos = 0;
        }
    }

    pthread_mutex_unlock(&b->lock);

    if (alert_kind)                   /* I/O fora da secao critica */
        emit_alert(alert_kind, ev, alert_count);
}

/* ---------------------------------------------------------------- threads */

static void *worker_thread(void *arg)
{
    long long *last = &worker_last_ns[(intptr_t)arg];
    event_t ev;
    while (queue_pop(&ev) == 0) {
        process_event(&ev);
        atomic_fetch_add(&events_processed, 1);
        *last = now_ns();
    }
    return NULL;
}

static int parse_line(const char *line, event_t *ev)
{
    if (sscanf(line, "%31[^|]|%45[^|]|%15[^|]|%31[^|\r\n]",
               ev->agent, ev->ip, ev->event, ev->user) != 4)
        return -1;
    ev->ts = time(NULL);
    return 0;
}

static void handle_line(const char *line)
{
    event_t ev;
    if (parse_line(line, &ev) != 0) {
        atomic_fetch_add(&parse_errors, 1);
        return;
    }
    atomic_fetch_add(&events_received, 1);
    if (atomic_load(&first_event_ns) == 0) {
        long long zero = 0;
        atomic_compare_exchange_strong(&first_event_ns, &zero, now_ns());
    }
    queue_push(&ev);
}

/* Uma thread por conexao de agente (produtor). */
static void *client_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char buf[RECV_BUF];
    size_t len = 0;

    while (!atomic_load(&g_stop)) {
        ssize_t n = recv(fd, buf + len, sizeof buf - len - 1, 0);
        if (n == 0)
            break;                                   /* agente desconectou */
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;                            /* timeout: rechecar g_stop */
            break;
        }
        len += (size_t)n;

        char *start = buf, *nl;
        while ((nl = memchr(start, '\n', (size_t)(buf + len - start))) != NULL) {
            *nl = '\0';
            handle_line(start);
            start = nl + 1;
        }
        len = (size_t)(buf + len - start);
        memmove(buf, start, len);
        if (len >= sizeof buf - 1)                   /* linha gigante: descarta */
            len = 0;
    }
    close(fd);
    atomic_fetch_sub(&clients_active, 1);
    return NULL;
}

static void *stats_thread(void *arg)
{
    (void)arg;
    unsigned long long last = 0;
    int tick = 0;
    while (!atomic_load(&g_stop)) {
        sleep(1);
        if (++tick < g_stats_interval)
            continue;
        tick = 0;
        unsigned long long done = atomic_load(&events_processed);
        printf("[stats] clientes=%d recebidos=%llu processados=%llu "
               "fila=%d alertas=%llu vazao=%llu ev/s\n",
               atomic_load(&clients_active), atomic_load(&events_received), done,
               queue_depth(), atomic_load(&alerts_total),
               (done - last) / (unsigned long long)g_stats_interval);
        fflush(stdout);
        last = done;
    }
    return NULL;
}

static void on_signal(int sig)
{
    (void)sig;
    atomic_store(&g_stop, 1);
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    const char *alert_path = "alerts.log";
    int opt;

    while ((opt = getopt(argc, argv, "p:w:o:c:i:")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'w': g_workers = atoi(optarg); break;
        case 'o': alert_path = optarg; break;
        case 'c': g_work_us = atoi(optarg); break;
        case 'i': g_stats_interval = atoi(optarg); break;
        default:
            fprintf(stderr,
                    "Uso: %s [-p porta] [-w workers] [-o alertas.log] [-c custo_us] [-i stats_s]\n",
                    argv[0]);
            return 1;
        }
    }
    if (g_workers < 1)
        g_workers = 1;
    if (g_stats_interval < 1)
        g_stats_interval = 1;

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    for (int i = 0; i < N_BUCKETS; i++)
        pthread_mutex_init(&table[i].lock, NULL);

    alert_fp = fopen(alert_path, "a");
    if (!alert_fp)
        perror("aviso: nao foi possivel abrir o arquivo de alertas");

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((uint16_t)port),
    };
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 128) < 0) { perror("listen"); return 1; }

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    pthread_t *workers = calloc((size_t)g_workers, sizeof *workers);
    worker_last_ns = calloc((size_t)g_workers, sizeof *worker_last_ns);
    for (int i = 0; i < g_workers; i++)
        pthread_create(&workers[i], NULL, worker_thread, (void *)(intptr_t)i);
    pthread_t stats;
    pthread_create(&stats, NULL, stats_thread, NULL);

    printf("Mini-SIEM escutando na porta %d (%d workers, custo extra %d us/evento)\n",
           port, g_workers, g_work_us);
    fflush(stdout);

    while (!atomic_load(&g_stop)) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        int r = poll(&pfd, 1, 1000);
        if (r <= 0)
            continue;                      /* timeout ou EINTR: rechecar g_stop */

        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0)
            continue;
        struct timeval tv = { .tv_sec = 1 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        atomic_fetch_add(&clients_active, 1);
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &attr, client_thread, (void *)(intptr_t)cfd) != 0) {
            close(cfd);
            atomic_fetch_sub(&clients_active, 1);
        }
        pthread_attr_destroy(&attr);
    }

    /* ---- encerramento limpo ---- */
    printf("\nEncerrando...\n");
    close(lfd);
    pthread_mutex_lock(&q.lock);           /* travar antes de acordar evita perda de sinal */
    pthread_cond_broadcast(&q.not_empty);
    pthread_cond_broadcast(&q.not_full);
    pthread_mutex_unlock(&q.lock);

    for (int i = 0; i < g_workers; i++)
        pthread_join(workers[i], NULL);
    pthread_join(stats, NULL);
    for (int i = 0; i < 50 && atomic_load(&clients_active) > 0; i++)
        usleep(100000);                    /* espera clientes (ate 5 s) */

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double secs = (double)(t_end.tv_sec - t_start.tv_sec) +
                  (double)(t_end.tv_nsec - t_start.tv_nsec) / 1e9;
    long long first = atomic_load(&first_event_ns), last = 0;
    for (int i = 0; i < g_workers; i++)
        if (worker_last_ns[i] > last)
            last = worker_last_ns[i];
    double window = (first > 0 && last > first) ? (double)(last - first) / 1e9 : 0.0;
    unsigned long long done = atomic_load(&events_processed);
    printf("RESUMO workers=%d recebidos=%llu processados=%llu alertas=%llu "
           "erros_parse=%llu tempo=%.1fs janela=%.2fs vazao=%.0f ev/s\n",
           g_workers, atomic_load(&events_received), done,
           atomic_load(&alerts_total), atomic_load(&parse_errors), secs,
           window, window > 0 ? (double)done / window : 0.0);

    if (alert_fp)
        fclose(alert_fp);
    free(workers);
    free(worker_last_ns);
    return 0;
}
