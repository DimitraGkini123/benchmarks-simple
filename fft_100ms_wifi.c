#include <string.h>
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/ip4_addr.h"
#include "hardware/sync.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "sha256.h"
#include "pico/stdlib.h"
#include "hardware/timer.h"

// ===================== DWT registers =====================
#define DEMCR                (*(volatile uint32_t *)0xE000EDFC)
#define DEMCR_TRCENA         (1u << 24)

#define DWT_BASE             (0xE0001000u)
#define DWT_CTRL             (*(volatile uint32_t *)(DWT_BASE + 0x000))
#define DWT_CYCCNT           (*(volatile uint32_t *)(DWT_BASE + 0x004))
#define DWT_CPICNT           (*(volatile uint32_t *)(DWT_BASE + 0x008))
#define DWT_EXCCNT           (*(volatile uint32_t *)(DWT_BASE + 0x00C))
#define DWT_SLEEPCNT         (*(volatile uint32_t *)(DWT_BASE + 0x010))
#define DWT_LSUCNT           (*(volatile uint32_t *)(DWT_BASE + 0x014))
#define DWT_FOLDCNT          (*(volatile uint32_t *)(DWT_BASE + 0x018))
#define DWT_LAR              (*(volatile uint32_t *)(DWT_BASE + 0xFB0))

#define DWT_CTRL_CYCCNTENA   (1u << 0)
#define DWT_CTRL_CPIEVTENA   (1u << 17)
#define DWT_CTRL_EXCEVTENA   (1u << 18)
#define DWT_CTRL_SLEEPEVTENA (1u << 19)
#define DWT_CTRL_LSUEVTENA   (1u << 20)
#define DWT_CTRL_FOLDEVTENA  (1u << 21)

#define DEVICE_ID 2

#ifndef VERIFIER_IP
#define VERIFIER_IP "192.168.68.102"
#endif
#ifndef VERIFIER_PORT
#define VERIFIER_PORT 4242
#endif

// ------- Partial attestation config -------
#define FW_BLOCKS_N    64
#define MAX_REQ_BLOCKS 32

// linker symbols provided by Pico toolchain
extern const uint8_t __flash_binary_start;
extern const uint8_t __flash_binary_end;

// ===================== Forward declarations =====================
static void comm_poll_parse(void);
static inline void net_service(void);
static void comm_ensure_connected(void);

static bool comm_wifi_init_once(void);
static bool comm_tcp_connect(void);
static void comm_tcp_close(void);

// lwIP callbacks
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  tcp_err_cb(void *arg, err_t err);
static err_t tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err);

// ===================== DWT enable =====================
static inline void dwt_enable_all(void) {
    DEMCR |= DEMCR_TRCENA;
    DWT_LAR = 0xC5ACCE55;

    DWT_CYCCNT   = 0;
    DWT_CPICNT   = 0;
    DWT_EXCCNT   = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT   = 0;
    DWT_FOLDCNT  = 0;

    DWT_CTRL |= DWT_CTRL_CYCCNTENA |
                DWT_CTRL_CPIEVTENA |
                DWT_CTRL_EXCEVTENA |
                DWT_CTRL_SLEEPEVTENA |
                DWT_CTRL_LSUEVTENA |
                DWT_CTRL_FOLDEVTENA;
}

// code injection for dummies
__attribute__((used))
static void fw_dummy_never_called(void) {
    volatile uint32_t x = 0x12345678u;
    (void)x;
}

// ===================== SHA helpers =====================
static void to_hex(const uint8_t *in, size_t n, char *out_hex /* size 2n+1 */) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out_hex[2*i+0] = H[(in[i] >> 4) & 0xF];
        out_hex[2*i+1] = H[in[i] & 0xF];
    }
    out_hex[2*n] = 0;
}

static void compute_fw_hash(uint8_t out_hash[32]) {
    const uint8_t *start = &__flash_binary_start;
    const uint8_t *end   = &__flash_binary_end;
    size_t len = (size_t)(end - start);

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, start, len);
    sha256_final(&ctx, out_hash);
}

static void compute_nonce_bound_response(const uint8_t *nonce, size_t nonce_len,
                                         const uint8_t fw_hash[32],
                                         uint8_t out_resp[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, nonce, nonce_len);
    sha256_update(&ctx, fw_hash, 32);
    sha256_final(&ctx, out_resp);
}

static bool compute_fw_block_hash(uint32_t block_idx, uint8_t out_hash[32],
                                  uint32_t *out_off, uint32_t *out_len) {
    const uint8_t *start = &__flash_binary_start;
    const uint8_t *end   = &__flash_binary_end;

    size_t fw_len = (size_t)(end - start);
    if (fw_len == 0) return false;
    if (block_idx >= FW_BLOCKS_N) return false;

    size_t block_size = (fw_len + (FW_BLOCKS_N - 1)) / FW_BLOCKS_N;

    size_t off = (size_t)block_idx * block_size;
    if (off >= fw_len) return false;

    size_t len = block_size;
    if (off + len > fw_len) len = fw_len - off;

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, start + off, len);
    sha256_final(&ctx, out_hash);

    if (out_off) *out_off = (uint32_t)off;
    if (out_len) *out_len = (uint32_t)len;
    return true;
}

static int parse_indices_list(const char *line, uint32_t *out, int out_max) {
    const char *p = strstr(line, "\"indices\":[");
    if (!p) return 0;
    p += strlen("\"indices\":[");

    int n = 0;
    while (*p && *p != ']' && n < out_max) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == ']') break;

        char *endptr = NULL;
        long v = strtol(p, &endptr, 10);
        if (endptr == p) break;
        if (v < 0) v = 0;
        out[n++] = (uint32_t)v;
        p = endptr;
    }
    return n;
}

// ===================== FFT workload pipeline =====================
#define FFT_N 256
#define FS_HZ 250.0
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif


typedef struct { double r, i; } cpx_t;

static cpx_t fft_buf[FFT_N];
static double mag[FFT_N / 2];
static volatile double fft_sink = 0.0;

static inline cpx_t c_add(cpx_t a, cpx_t b) { return (cpx_t){a.r + b.r, a.i + b.i}; }
static inline cpx_t c_sub(cpx_t a, cpx_t b) { return (cpx_t){a.r - b.r, a.i - b.i}; }
static inline cpx_t c_mul(cpx_t a, cpx_t b) { return (cpx_t){a.r*b.r - a.i*b.i, a.r*b.i + a.i*b.r}; }

static void fft(cpx_t *buf, int n) {
    int i, j, k, m;

    // bit-reversal
    for (i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j |= bit;
        if (i < j) { cpx_t tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp; }
        if ((i & 31) == 0) net_service();
    }

    // Danielson–Lanczos
    for (m = 1; m < n; m <<= 1) {
        double ang = -M_PI / m;
        cpx_t wm = {cos(ang), sin(ang)};
        for (k = 0; k < n; k += (m << 1)) {
            cpx_t w = {1.0, 0.0};
            for (j = 0; j < m; j++) {
                cpx_t t = c_mul(w, buf[k + j + m]);
                cpx_t u = buf[k + j];
                buf[k + j]     = c_add(u, t);
                buf[k + j + m] = c_sub(u, t);
                w = c_mul(w, wm);
            }
            net_service();
        }
    }
}

static void compute_mag(void) {
    for (int k = 0; k < FFT_N/2; k++) {
        mag[k] = sqrt(fft_buf[k].r * fft_buf[k].r + fft_buf[k].i * fft_buf[k].i);
        if ((k & 31) == 0) net_service();
    }
}

static double band_energy(double f0, double f1) {
    int k0 = (int)(f0 * FFT_N / FS_HZ);
    int k1 = (int)(f1 * FFT_N / FS_HZ);
    if (k0 < 0) k0 = 0;
    if (k1 > (FFT_N/2 - 1)) k1 = (FFT_N/2 - 1);

    double e = 0.0;
    for (int k = k0; k <= k1; k++) {
        e += mag[k] * mag[k];
        if ((k & 31) == 0) net_service();
    }
    return e;
}

static void generate_fft_signal(double trem_freq, double trem_amp) {
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);

    for (int i = 0; i < FFT_N; i++) {
        double t = i / FS_HZ;
        double ecg   = 0.7 * sin(2 * M_PI * f_ecg * t);
        double trem  = trem_amp * sin(2 * M_PI * trem_freq * t);
        double noise = ((rand() % 2000) / 1000.0 - 1.0) * 0.03;

        fft_buf[i].r = ecg + trem + noise;
        fft_buf[i].i = 0.0;

        if ((i & 31) == 0) net_service();
    }
}

// ===================== Workload Router (FFT) =====================
static inline void run_workload_step(int label) {
    if (label == 0) { // LIGHT
        generate_fft_signal(4.0, 0.05);
        fft(fft_buf, FFT_N);
        compute_mag();
        fft_sink += band_energy(3.0, 10.0) / (band_energy(0.5, 3.0) + 1e-6);
        sleep_ms(2); // κρατάει λίγο "ανάσα" όπως πριν
    }
    else if (label == 1) { // MEDIUM
        generate_fft_signal(6.0, 0.25);
        fft(fft_buf, FFT_N);
        fft(fft_buf, FFT_N);  // extra work
        compute_mag();
        fft_sink += (band_energy(3.0, 10.0) + band_energy(10.0, 40.0)) / (band_energy(0.5, 3.0) + 1e-6);
    }
    else { // HEAVY
        generate_fft_signal(8.5, 0.50);
        for (int i = 0; i < 4; i++) fft(fft_buf, FFT_N); // more work
        compute_mag();

        double e1 = band_energy(0.5, 3.0);
        double e2 = band_energy(3.0, 10.0);
        double e3 = band_energy(10.0, 40.0);

        volatile double acc = 0.0;
        for (int i = 0; i < 500; i++) {
            acc += e3 / (e2 + 1e-6);
            acc *= 0.995;
            if ((i & 63) == 0) net_service();
        }
        fft_sink += acc;
    }
}

// ===================== Aggregator (2ms oversampling) =====================
typedef struct {
    uint32_t sum_cyc;
    uint32_t sum_lsu;
    uint32_t sum_cpi;
    uint32_t sum_exc;
    uint32_t sum_fold;
    uint32_t sum_sleep;
    uint32_t sum_dt_us;
} agg_t;

static volatile agg_t agg = (agg_t){0};

// previous readings for delta
static uint32_t prev_cyc = 0;
static uint64_t prev_t_us = 0;

static uint8_t prev_lsu8 = 0, prev_cpi8 = 0, prev_exc8 = 0, prev_fold8 = 0, prev_sleep8 = 0;

static inline uint8_t delta_u8(uint8_t curr, uint8_t prev) {
    return (uint8_t)(curr - prev);
}

// ===================== Ring buffer for 100ms samples =====================
typedef struct {
    uint32_t device_id;
    uint32_t window_id;
    uint32_t label;
    uint32_t dC, dL, dP, dE, dF, dS, dT;
    float cyc_per_us;
    float lsu_per_cyc;
    float cpi_per_cyc;
    float exc_per_cyc;
    float fold_per_cyc;
} sample_t;

#define RING_N 256
static volatile sample_t ring[RING_N];
static volatile uint32_t w_idx = 0;
static volatile uint32_t r_idx = 0;
static volatile uint32_t ring_dropped = 0;

static inline bool ring_push(const sample_t *s) {
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) {
        ring_dropped++;
        return false;
    }
    ring[w_idx] = *s;
    w_idx = next;
    return true;
}

// ===================== Global label/window =====================
static volatile uint32_t current_label = 0;
static volatile uint32_t window_id = 0;

// ===================== 2ms callback =====================
bool timer_2ms_cb(struct repeating_timer *t) {
    (void)t;

    uint64_t now = time_us_64();
    uint32_t dt = (uint32_t)(now - prev_t_us);
    prev_t_us = now;

    uint32_t cyc = DWT_CYCCNT;
    uint32_t dC = (uint32_t)(cyc - prev_cyc);
    prev_cyc = cyc;

    uint8_t lsu8   = (uint8_t)DWT_LSUCNT;
    uint8_t cpi8   = (uint8_t)DWT_CPICNT;
    uint8_t exc8   = (uint8_t)DWT_EXCCNT;
    uint8_t fold8  = (uint8_t)DWT_FOLDCNT;
    uint8_t sleep8 = (uint8_t)DWT_SLEEPCNT;

    uint8_t dL = delta_u8(lsu8,   prev_lsu8);
    uint8_t dP = delta_u8(cpi8,   prev_cpi8);
    uint8_t dE = delta_u8(exc8,   prev_exc8);
    uint8_t dF = delta_u8(fold8,  prev_fold8);
    uint8_t dS = delta_u8(sleep8, prev_sleep8);

    prev_lsu8 = lsu8; prev_cpi8 = cpi8; prev_exc8 = exc8; prev_fold8 = fold8; prev_sleep8 = sleep8;

    agg.sum_dt_us += dt;
    agg.sum_cyc   += dC;
    agg.sum_lsu   += dL;
    agg.sum_cpi   += dP;
    agg.sum_exc   += dE;
    agg.sum_fold  += dF;
    agg.sum_sleep += dS;

    return true;
}

// ===================== 100ms callback =====================
bool timer_100ms_cb(struct repeating_timer *t) {
    (void)t;

    agg_t a = agg;
    agg = (agg_t){0};

    float fdT = (a.sum_dt_us > 0) ? (float)a.sum_dt_us : 1.0f;
    float fdC = (a.sum_cyc   > 0) ? (float)a.sum_cyc   : 1.0f;

    sample_t s = (sample_t){0};
    s.device_id = DEVICE_ID;
    s.window_id = window_id++;
    s.label     = current_label;

    s.dT = a.sum_dt_us;
    s.dC = a.sum_cyc;
    s.dL = a.sum_lsu;
    s.dP = a.sum_cpi;
    s.dE = a.sum_exc;
    s.dF = a.sum_fold;
    s.dS = a.sum_sleep;

    s.cyc_per_us   = ((float)a.sum_cyc) / fdT;
    s.lsu_per_cyc  = ((float)a.sum_lsu) / fdC;
    s.cpi_per_cyc  = ((float)a.sum_cpi) / fdC;
    s.exc_per_cyc  = ((float)a.sum_exc) / fdC;
    s.fold_per_cyc = ((float)a.sum_fold)/ fdC;

    (void)ring_push(&s);
    return true;
}

// ===================== TCP comms globals =====================
static struct tcp_pcb *g_pcb = NULL;
static bool g_connected = false;

static char rxbuf[2048];
static int  rxlen = 0;
static volatile bool rx_dirty = false;

static char txbuf_windows[9000];
static char txbuf_attest[13000];

// ===================== WiFi/TCP state =====================
static bool wifi_ready = false;
static absolute_time_t next_reconnect_at;

// ===================== send helper =====================
static bool comm_send_all(const char *buf, size_t len) {
    if (!g_connected || !g_pcb) return false;

    size_t off = 0;
    while (off < len) {
        cyw43_arch_poll();

        cyw43_arch_lwip_begin();

        if (!g_pcb) {
            cyw43_arch_lwip_end();
            g_connected = false;
            return false;
        }

        u16_t space = tcp_sndbuf(g_pcb);
        if (space == 0) {
            cyw43_arch_lwip_end();
            sleep_ms(1);
            continue;
        }

        u16_t chunk = (u16_t)(((len - off) < (size_t)space) ? (len - off) : (size_t)space);

        err_t e = tcp_write(g_pcb, buf + off, chunk, TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK) {
            err_t eo = tcp_output(g_pcb);
            cyw43_arch_lwip_end();

            if (eo == ERR_OK) {
                off += chunk;
                continue;
            }
            e = eo;
        } else {
            cyw43_arch_lwip_end();
        }

        if (e == ERR_MEM || e == ERR_WOULDBLOCK) {
            sleep_ms(2);
            continue;
        }

        if (e == ERR_CONN || e == ERR_CLSD || e == ERR_RST || e == ERR_ABRT) {
            g_connected = false;
            g_pcb = NULL;
            return false;
        }

        sleep_ms(2);
        g_connected = false;
        g_pcb = NULL;
        return false;
    }

    return true;
}

static void comm_send_str(const char *s) {
    (void)comm_send_all(s, strlen(s));
}

// ===================== tiny req_id extractor =====================
static void extract_req_id(const char *line, char *out, int out_sz) {
    out[0] = 0;
    const char *p = strstr(line, "\"req_id\":\"");
    if (!p) return;
    p += strlen("\"req_id\":\"");
    const char *q = strchr(p, '"');
    if (!q) return;
    int n = (int)(q - p);
    if (n > 0 && n < out_sz) {
        memcpy(out, p, n);
        out[n] = 0;
    }
}

// ===================== request handler =====================
static void handle_line(char *line) {
    char req_id[64];
    extract_req_id(line, req_id, (int)sizeof(req_id));

    if (strstr(line, "\"type\":\"PING\"")) {
        char out[160];
        snprintf(out, sizeof(out), "{\"type\":\"PONG\",\"req_id\":\"%s\"}\n", req_id);
        comm_send_str(out);
        return;
    }

    if (strstr(line, "\"type\":\"GET_WINDOWS\"")) {
        char req_id2[64];
        extract_req_id(line, req_id2, (int)sizeof(req_id2));

        uint32_t since = 0;
        int maxn = 20;

        char *ps = strstr(line, "\"since\":");
        if (ps) since = (uint32_t)strtoul(ps + 8, NULL, 10);

        char *pm = strstr(line, "\"max\":");
        if (pm) maxn = (int)strtol(pm + 6, NULL, 10);
        if (maxn < 1) maxn = 1;
        if (maxn > 50) maxn = 50;

        // Snapshot ring indices (no pop) and build a response,
        // then advance r_idx ONLY if send ok.
        sample_t snap[50];
        int snap_n = 0;

        uint32_t r0, w0;
        uint32_t flags = save_and_disable_interrupts();
        r0 = r_idx;
        w0 = w_idx;
        restore_interrupts(flags);

        uint32_t avail = (w0 >= r0) ? (w0 - r0) : (RING_N - r0 + w0);
        int want = maxn;
        if (want > (int)avail) want = (int)avail;
        if (want > 50) want = 50;

        for (int i = 0; i < want; i++) {
            uint32_t ri = (r0 + (uint32_t)i) % RING_N;
            snap[snap_n++] = ring[ri];
        }

        uint32_t dropped_overflow_snapshot = ring_dropped;

        char *out = txbuf_windows;
        int out_sz = (int)sizeof(txbuf_windows);
        int pos = 0;

        pos += snprintf(out + pos, (size_t)(out_sz - pos),
            "{\"type\":\"WINDOWS\",\"req_id\":\"%s\",\"since\":%u,"
            "\"dropped_old\":%u,\"dropped_overflow\":%u,\"windows\":[",
            req_id2[0] ? req_id2 : "none",
            since,
            0u,
            dropped_overflow_snapshot
        );

        int sent = 0;
        uint32_t first_id = 0, last_id = 0;

        for (int i = 0; i < snap_n; i++) {
            sample_t s = snap[i];
            if (s.window_id <= since) continue;

            if (sent == 0) first_id = s.window_id;
            last_id = s.window_id;

            if (sent > 0) pos += snprintf(out + pos, (size_t)(out_sz - pos), ",");

            pos += snprintf(out + pos, (size_t)(out_sz - pos),
                "{\"window_id\":%u,\"label\":%u,\"dE\":%u,\"dS\":%u,\"dF\":%u,\"dL\":%u}",
                s.window_id, s.label, s.dE, s.dS, s.dF, s.dL
            );

            sent++;
            if (pos > out_sz - 240) break;
        }

        pos += snprintf(out + pos, (size_t)(out_sz - pos),
            "],\"from\":%u,\"to\":%u,\"count\":%d}\n",
            sent ? first_id : 0,
            sent ? last_id : 0,
            sent
        );

        bool ok = comm_send_all(out, (size_t)pos);

        if (ok) {
            uint32_t f = save_and_disable_interrupts();
            // advance read index for what we actually sent + old
            while (r_idx != w_idx) {
                sample_t cur = ring[r_idx];
                if (cur.window_id <= since) {
                    r_idx = (r_idx + 1u) % RING_N;
                } else {
                    break;
                }
            }
            if (sent > 0) {
                while (r_idx != w_idx) {
                    sample_t cur = ring[r_idx];
                    if (cur.window_id <= last_id) {
                        r_idx = (r_idx + 1u) % RING_N;
                    } else {
                        break;
                    }
                }
            }
            restore_interrupts(f);
        }

        return;
    }

    if (strstr(line, "\"type\":\"ATTEST_REQUEST\"")) {
        char req_id2[64];
        extract_req_id(line, req_id2, (int)sizeof(req_id2));

        bool is_full    = (strstr(line, "\"mode\":\"FULL_HASH_PROVER\"") != NULL);
        bool is_partial = (strstr(line, "\"mode\":\"PARTIAL_BLOCKS\"") != NULL);

        if (!is_full && !is_partial) {
            char out[220];
            snprintf(out, sizeof(out),
                     "{\"type\":\"ERROR\",\"req_id\":\"%s\",\"reason\":\"unknown_attest_mode\"}\n",
                     req_id2[0] ? req_id2 : "none");
            comm_send_str(out);
            return;
        }

        char nonce_hex[128] = {0};
        const char *pn = strstr(line, "\"nonce\":\"");
        if (!pn) {
            char out[180];
            snprintf(out, sizeof(out),
                     "{\"type\":\"ERROR\",\"req_id\":\"%s\",\"reason\":\"missing_nonce\"}\n",
                     req_id2[0] ? req_id2 : "none");
            comm_send_str(out);
            return;
        }
        pn += strlen("\"nonce\":\"");
        const char *qn = strchr(pn, '"');
        if (!qn) {
            char out[180];
            snprintf(out, sizeof(out),
                     "{\"type\":\"ERROR\",\"req_id\":\"%s\",\"reason\":\"bad_nonce\"}\n",
                     req_id2[0] ? req_id2 : "none");
            comm_send_str(out);
            return;
        }
        int nhex = (int)(qn - pn);
        if (nhex <= 0 || nhex >= (int)sizeof(nonce_hex)) nhex = (int)sizeof(nonce_hex) - 1;
        memcpy(nonce_hex, pn, (size_t)nhex);
        nonce_hex[nhex] = 0;

        uint8_t nonce[64];
        size_t nonce_len = 0;
        for (int i = 0; i + 1 < nhex && nonce_len < sizeof(nonce); i += 2) {
            char a = nonce_hex[i], b = nonce_hex[i+1];
            uint8_t hi = (a <= '9') ? (a - '0') : ((a | 32) - 'a' + 10);
            uint8_t lo = (b <= '9') ? (b - '0') : ((b | 32) - 'a' + 10);
            nonce[nonce_len++] = (uint8_t)((hi << 4) | lo);
        }

        if (is_partial) {
            uint32_t idxs[MAX_REQ_BLOCKS];
            int k = parse_indices_list(line, idxs, MAX_REQ_BLOCKS);
            bool provision_all = (k == 0);

            char *out = txbuf_attest;
            int out_sz = (int)sizeof(txbuf_attest);
            int pos = 0;

            pos += snprintf(out + pos, (size_t)(out_sz - pos),
                "{\"type\":\"ATTEST_RESPONSE\",\"req_id\":\"%s\",\"mode\":\"PARTIAL_BLOCKS\",\"region\":\"fw\","
                "\"block_count\":%u,\"blocks\":[",
                req_id2[0] ? req_id2 : "none",
                (unsigned)FW_BLOCKS_N
            );

            int sent = 0;
            int limit = provision_all ? (int)FW_BLOCKS_N : k;

            for (int i = 0; i < limit; i++) {
                uint32_t bi = provision_all ? (uint32_t)i : idxs[i];

                uint8_t bh[32];
                uint32_t off = 0, blen = 0;
                if (!compute_fw_block_hash(bi, bh, &off, &blen)) continue;

                uint8_t resp[32];
                compute_nonce_bound_response(nonce, nonce_len, bh, resp);

                char bh_hex[65];
                char resp_hex[65];
                to_hex(bh, 32, bh_hex);
                to_hex(resp, 32, resp_hex);

                if (sent > 0) pos += snprintf(out + pos, (size_t)(out_sz - pos), ",");

                pos += snprintf(out + pos, (size_t)(out_sz - pos),
                    "{\"index\":%u,\"off\":%u,\"len\":%u,\"hash_hex\":\"%s\",\"response_hex\":\"%s\"}",
                    (unsigned)bi, (unsigned)off, (unsigned)blen, bh_hex, resp_hex
                );

                sent++;
                if (pos > out_sz - 240) break;
            }

            pos += snprintf(out + pos, (size_t)(out_sz - pos), "],\"count\":%d}\n", sent);
            comm_send_str(out);
            return;
        }

        if (is_full) {
            uint8_t fw_hash[32], resp[32];
            compute_fw_hash(fw_hash);
            compute_nonce_bound_response(nonce, nonce_len, fw_hash, resp);

            char fw_hex[65], resp_hex[65];
            to_hex(fw_hash, 32, fw_hex);
            to_hex(resp, 32, resp_hex);

            char out[420];
            snprintf(out, sizeof(out),
                "{\"type\":\"ATTEST_RESPONSE\",\"req_id\":\"%s\",\"mode\":\"FULL_HASH_PROVER\",\"region\":\"fw\","
                "\"fw_hash_hex\":\"%s\",\"response_hex\":\"%s\"}\n",
                req_id2[0] ? req_id2 : "none", fw_hex, resp_hex);

            comm_send_str(out);
            return;
        }
    }

    {
        char out[220];
        snprintf(out, sizeof(out),
                 "{\"type\":\"ERROR\",\"req_id\":\"%s\",\"reason\":\"unknown_request\"}\n",
                 req_id[0] ? req_id : "none");
        comm_send_str(out);
    }
}

// ===================== parse buffered rx =====================
static void comm_poll_parse(void) {
    if (!rx_dirty) return;
    rx_dirty = false;

    char *start = rxbuf;
    while (1) {
        char *nl = strchr(start, '\n');
        if (!nl) break;
        *nl = 0;
        if (*start) handle_line(start);
        start = nl + 1;
    }

    int remaining = (int)(rxbuf + rxlen - start);
    memmove(rxbuf, start, (size_t)remaining);
    rxlen = remaining;
}

// ===================== net_service =====================
static inline void net_service(void) {
    cyw43_arch_poll();
    comm_poll_parse();
    comm_ensure_connected();
}

// ===================== lwIP recv callback =====================
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) {
        // remote closed
        g_connected = false;
        g_pcb = NULL;
        return ERR_OK;
    }

    tcp_recved(tpcb, p->tot_len);

    if (rxlen + (int)p->tot_len < (int)sizeof(rxbuf) - 1) {
        pbuf_copy_partial(p, rxbuf + rxlen, p->tot_len, 0);
        rxlen += (int)p->tot_len;
        rxbuf[rxlen] = 0;
        rx_dirty = true;
    }
    pbuf_free(p);
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
    (void)arg; (void)err;
    // lwIP already freed pcb; mark disconnected
    g_connected = false;
    g_pcb = NULL;
}

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK) return err;

    g_connected = true;
    g_pcb = tpcb;

    char hello[128];
    snprintf(hello, sizeof(hello),
         "{\"type\":\"HELLO\",\"device_id\":\"pico2w_%u\","
         "\"fw_blocks_n\":%u,"
         "\"max_req_blocks\":%u}\n",
         DEVICE_ID,
         (unsigned)FW_BLOCKS_N,
         (unsigned)MAX_REQ_BLOCKS);
    comm_send_str(hello);

    return ERR_OK;
}

// ===================== WiFi init ONCE =====================
static bool comm_wifi_init_once(void) {
    if (wifi_ready) return true;

    if (cyw43_arch_init()) {
        printf("cyw43_arch_init failed\n");
        return false;
    }
    cyw43_arch_enable_sta_mode();

    const char *ssid = "Get your own";
    const char *pass = "igataeinaiteleia";

    printf("Connecting WiFi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(ssid, pass, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("WiFi connect FAILED\n");
        return false;
    }
    printf("WiFi OK\n");
    wifi_ready = true;

    printf("VERIFIER_IP=%s PORT=%d\n", VERIFIER_IP, VERIFIER_PORT);

    ip4_addr_t myip = *netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_STA]);
    printf("Pico IP: %s\n", ip4addr_ntoa(&myip));

    return true;
}

// ===================== TCP close helper =====================
static void comm_tcp_close(void) {
    if (!g_pcb) return;

    cyw43_arch_lwip_begin();
    tcp_arg(g_pcb, NULL);
    tcp_recv(g_pcb, NULL);
    tcp_err(g_pcb, NULL);
    tcp_abort(g_pcb); // frees pcb immediately
    cyw43_arch_lwip_end();

    g_pcb = NULL;
    g_connected = false;
}

// ===================== TCP connect only =====================
static bool comm_tcp_connect(void) {
    if (!wifi_ready) return false;

    ip4_addr_t addr;
    int ok = ip4addr_aton(VERIFIER_IP, &addr);
    printf("ip4addr_aton ok=%d\n", ok);
    if (!ok) return false;

    // nuke any old pcb
    comm_tcp_close();

    cyw43_arch_lwip_begin();
    g_pcb = tcp_new();
    if (!g_pcb) {
        cyw43_arch_lwip_end();
        printf("tcp_new failed\n");
        return false;
    }

    tcp_recv(g_pcb, tcp_recv_cb);
    tcp_err(g_pcb, tcp_err_cb);

    err_t e = tcp_connect(g_pcb, (ip_addr_t*)&addr, VERIFIER_PORT, tcp_connected_cb);
    printf("tcp_connect() returned %d\n", (int)e);

    cyw43_arch_lwip_end();

    if (e != ERR_OK) {
        comm_tcp_close();
        return false;
    }
    return true;
}

// ===================== reconnect with backoff =====================
static void comm_ensure_connected(void) {
    if (g_connected && g_pcb) return;

    if (!time_reached(next_reconnect_at)) return;
    next_reconnect_at = make_timeout_time_ms(2000);

    printf("reconnecting...\n");

    // IMPORTANT: do NOT re-init wifi on reconnect
    if (!comm_wifi_init_once()) return;
    (void)comm_tcp_connect();
}

// ===================== main =====================
int main(void) {
    stdio_init_all();
    dwt_enable_all();

    next_reconnect_at = make_timeout_time_ms(0);

    (void)comm_wifi_init_once();
    (void)comm_tcp_connect();

    // init prevs
    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    // timers
    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    const uint32_t windows_per_class = 300;

    for (int phase = 0; phase < 3; phase++) {
        current_label = (uint32_t)phase;
        uint32_t end_window = window_id + windows_per_class;

        while (1) {
            net_service();                 // keep stack alive (poll+parse+reconnect)
            run_workload_step((int)current_label);

            uint32_t wid_now;
            uint32_t flags = save_and_disable_interrupts();
            wid_now = window_id;
            restore_interrupts(flags);

            if (wid_now >= end_window) break;
        }
    }

    while (1) {
        net_service();
        sleep_ms(1000);
    }
}
