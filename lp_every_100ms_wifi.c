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

#define DEVICE_ID 1
#ifndef WIFI_SSID
#define WIFI_SSID "YOUR_SSID"
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "YOUR_PASS"
#endif
#ifndef VERIFIER_IP
#define VERIFIER_IP "192.168.68.123"
#endif
#ifndef VERIFIER_PORT
#define VERIFIER_PORT 4242
#endif
// linker symbols provided by Pico toolchain
extern const uint8_t __flash_binary_start;
extern const uint8_t __flash_binary_end;

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
//code injection for dummies 
__attribute__((used))
static void fw_dummy_never_called(void) {
    // never called
    volatile uint32_t x = 0x12345678u;
    (void)x;
}

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


// ===================== Your signal pipeline =====================
#define LEN 512
static double sig_in[LEN];
static double sig_filt[LEN];

#define LPF_ORDER 8
static const double lp_coefficients[LPF_ORDER] = {
    -0.00511, 0.01017, 0.05730, 0.20164,
    0.47291, 0.20164, 0.05730, 0.01017
};

static void generate_light_signal(double fs) {
    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double f_ecg = 1.0 + ((rand()%40)/100.0);
        double ecg = 0.7 * sin(2*M_PI*f_ecg * t);
        double tremor_amp = 0.05 + ((rand()%50)/1000.0);
        double tremor = tremor_amp * sin(2*M_PI*4.0 * t);
        double noise  = ((rand()%2000)/1000.0 - 1.0) * 0.02;
        sig_in[i] = ecg + tremor + noise;
    }
}

static void generate_medium_signal(double fs) {
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);
    double f_tremor = 5.5 + ((rand() % 100) / 100.0);
    double tremor_amp = 0.25 + ((rand() % 100) / 1000.0);
    double noise_amp = 0.03 + ((rand() % 20) / 1000.0);

    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * f_ecg * t);
        double tremor = tremor_amp * sin(2 * M_PI * f_tremor * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * noise_amp;
        sig_in[i] = ecg + tremor + noise;
    }
}

static void generate_heavy_signal(double fs) {
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);
    double f_tremor = 7.5 + ((rand() % 150) / 100.0);
    double tremor_amp = 0.5 + ((rand() % 200) / 1000.0);
    double noise_amp = 0.06 + ((rand() % 30) / 1000.0);

    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * f_ecg * t);
        double tremor = tremor_amp * sin(2 * M_PI * f_tremor * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * noise_amp;
        sig_in[i] = ecg + tremor + noise;
    }
}

static void low_pass_fir(const double *in, double *out, size_t len,
                         const double *h, int M) {
    for (size_t n = 0; n < len; ++n) {
        double sum = 0.0;
        int kmax = (n < (size_t)(M - 1)) ? (int)n : (M - 1);
        for (int k = 0; k <= kmax; ++k) {
            sum += h[k] * in[n - (size_t)k];
        }
        out[n] = sum;
    }
}

static double compute_hr(const double *x, size_t len, double fs, double thr) {
    if (!x || len < 3 || fs <= 0.0) return 0.0;

    int peaks = 0;
    for (size_t i = 1; i + 1 < len; i++) {
        if (x[i] > x[i - 1] && x[i] > x[i + 1] && x[i] > thr) {
            peaks++;
            size_t skip = (size_t)(fs * 0.4);
            i += skip;
            if (i + 1 >= len) break;
        }
    }

    double dur = (double)len / fs;
    return dur > 0 ? (peaks / dur) * 60.0 : 0.0;
}

static volatile double hr_sink = 0.0;

static inline void run_workload_step(int label) {
    const double fs = 250.0;

    if (label == 0) generate_light_signal(fs);
    else if (label == 1) generate_medium_signal(fs);
    else generate_heavy_signal(fs);

    low_pass_fir(sig_in, sig_filt, LEN, lp_coefficients, LPF_ORDER);

    if (label == 1) {
        low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    } else if (label == 2) {
        for (int k = 0; k < 3; ++k) low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    }

    hr_sink += compute_hr(sig_filt, LEN, fs, 0.2);

    // make LIGHT a bit more idle without relying on SLEEPCNT correctness
    if (label == 0) sleep_ms(2);
}

// ===================== Aggregator (2ms oversampling) =====================
typedef struct {
    // accumulated over 100ms window
    uint32_t sum_cyc;     // from CYCCNT deltas (32-bit safe)
    uint32_t sum_lsu;     // from 8-bit counters oversampled
    uint32_t sum_cpi;
    uint32_t sum_exc;
    uint32_t sum_fold;
    uint32_t sum_sleep;
    uint32_t sum_dt_us;   // should end near 100000
} agg_t;

static volatile agg_t agg = {0};

// previous readings for delta
static uint32_t prev_cyc = 0;
static uint64_t prev_t_us = 0;

static uint8_t prev_lsu8 = 0, prev_cpi8 = 0, prev_exc8 = 0, prev_fold8 = 0, prev_sleep8 = 0;

// wrap-safe 8-bit delta
static inline uint8_t delta_u8(uint8_t curr, uint8_t prev) {
    return (uint8_t)(curr - prev); // unsigned wrap (mod 256) is desired
}

// ===================== Ring buffer for 100ms samples =====================
typedef struct {
    uint32_t device_id;
    uint32_t window_id;
    uint32_t label;

    // raw aggregates
    uint32_t dC, dL, dP, dE, dF, dS, dT;

    // features (ratios)
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

static inline bool ring_pop(sample_t *out) {
    if (r_idx == w_idx) return false;
    *out = ring[r_idx];
    r_idx = (r_idx + 1u) % RING_N;
    return true;
}

// ===================== Global label/window =====================
static volatile uint32_t current_label = 0;
static volatile uint32_t window_id = 0;

// ===================== 2ms callback: oversample DWT =====================
bool timer_2ms_cb(struct repeating_timer *t) {
    (void)t;

    // time delta
    uint64_t now = time_us_64();
    uint32_t dt = (uint32_t)(now - prev_t_us);
    prev_t_us = now;

    // cyccnt delta (32-bit wrap-safe)
    uint32_t cyc = DWT_CYCCNT;
    uint32_t dC = (uint32_t)(cyc - prev_cyc);
    prev_cyc = cyc;

    // 8-bit event counters (read low 8 bits)
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

    // accumulate
    agg.sum_dt_us += dt;
    agg.sum_cyc   += dC;
    agg.sum_lsu   += dL;
    agg.sum_cpi   += dP;
    agg.sum_exc   += dE;
    agg.sum_fold  += dF;
    agg.sum_sleep += dS;

    return true;
}

// ===================== 100ms callback: create one sample =====================
bool timer_100ms_cb(struct repeating_timer *t) {
    (void)t;

    // snapshot + reset aggregator (single-writer in IRQ; acceptable)
    agg_t a = agg;
    agg = (agg_t){0};

    float fdT = (a.sum_dt_us > 0) ? (float)a.sum_dt_us : 1.0f;
    float fdC = (a.sum_cyc   > 0) ? (float)a.sum_cyc   : 1.0f;

    sample_t s = {0};
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

    s.cyc_per_us  = ((float)a.sum_cyc) / fdT;
    s.lsu_per_cyc = ((float)a.sum_lsu) / fdC;
    s.cpi_per_cyc = ((float)a.sum_cpi) / fdC;
    s.exc_per_cyc = ((float)a.sum_exc) / fdC;
    s.fold_per_cyc= ((float)a.sum_fold)/ fdC;

    (void)ring_push(&s);
    return true;
}
static struct tcp_pcb *g_pcb = NULL;
static bool g_connected = false;

static char rxbuf[2048];
static int  rxlen = 0;
static volatile bool rx_dirty = false;

// send (safe from main loop)
/*static void comm_send_str(const char *s) {
    if (!g_connected || !g_pcb) return;

    cyw43_arch_lwip_begin();
    err_t e = tcp_write(g_pcb, s, (u16_t)strlen(s), TCP_WRITE_FLAG_COPY);
    if (e == ERR_OK) tcp_output(g_pcb);
    cyw43_arch_lwip_end();
}
    */
static bool comm_send_all(const char *buf, size_t len) {
    if (!g_connected || !g_pcb) return false;

    size_t off = 0;
    while (off < len) {
        cyw43_arch_lwip_begin();

        // πόσο χώρο έχουμε στο TCP send buffer
        u16_t space = tcp_sndbuf(g_pcb);

        if (space == 0) {
            // δεν υπάρχει χώρος τώρα -> δοκίμασε αργότερα
            cyw43_arch_lwip_end();
            sleep_ms(1);
            continue;
        }

        // στείλε μέχρι όσο χωράει
        u16_t chunk = (u16_t)((len - off) < (size_t)space ? (len - off) : (size_t)space);

        err_t e = tcp_write(g_pcb, buf + off, chunk, TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK) {
            tcp_output(g_pcb);
            off += chunk;
            cyw43_arch_lwip_end();
        } else {
            // ERR_MEM ή άλλο transient
            cyw43_arch_lwip_end();
            sleep_ms(1);
        }
    }
    return true;
}

static void comm_send_str(const char *s) {
    (void)comm_send_all(s, strlen(s));
}


// very tiny req_id extractor: finds "req_id":"...."
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
static bool ring_peek_oldest(sample_t *out) {
    uint32_t flags = save_and_disable_interrupts();
    if (r_idx == w_idx) {
        restore_interrupts(flags);
        return false;
    }
    *out = ring[r_idx];
    restore_interrupts(flags);
    return true;
}

static bool ring_pop_oldest(sample_t *out) {
    uint32_t flags = save_and_disable_interrupts();
    if (r_idx == w_idx) {
        restore_interrupts(flags);
        return false;
    }
    *out = ring[r_idx];
    r_idx = (r_idx + 1u) % RING_N;
    restore_interrupts(flags);
    return true;
}

static void handle_line(char *line) {
    char req_id[64];
    extract_req_id(line, req_id, (int)sizeof(req_id));

    if (strstr(line, "\"type\":\"PING\"")) {
        char out[160];
        snprintf(out, sizeof(out), "{\"type\":\"PONG\",\"req_id\":\"%s\"}\n", req_id);
        comm_send_str(out);
        return;
    }

    // get windows handler 
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

    // drop old windows <= since
    uint32_t dropped_old = 0;
    while (1) {
        sample_t tmp;
        if (!ring_peek_oldest(&tmp)) break;
        if (tmp.window_id <= since) {
            (void)ring_pop_oldest(&tmp);
            dropped_old++;
        } else {
            break;
        }
    }

    uint32_t dropped_overflow_snapshot = ring_dropped;

    char out[8192];
    int pos = 0;

    pos += snprintf(out + pos, sizeof(out) - pos,
        "{\"type\":\"WINDOWS\",\"req_id\":\"%s\",\"since\":%u,"
        "\"dropped_old\":%u,\"dropped_overflow\":%u,\"windows\":[",
        req_id2[0] ? req_id2 : "none",
        since, dropped_old, dropped_overflow_snapshot
    );

    int sent = 0;
    uint32_t first_id = 0, last_id = 0;

    for (int i = 0; i < maxn; i++) {
        sample_t s;
        if (!ring_pop_oldest(&s)) break;

        if (sent == 0) first_id = s.window_id;
        last_id = s.window_id;

        if (sent > 0) pos += snprintf(out + pos, sizeof(out) - pos, ",");

        pos += snprintf(out + pos, sizeof(out) - pos,
            "{\"device_id\":%u,\"window_id\":%u,\"label\":%u,"
            "\"dC\":%u,\"dL\":%u,\"dP\":%u,\"dE\":%u,\"dF\":%u,\"dS\":%u,\"dT\":%u,"
            "\"cyc_per_us\":%.6f,\"lsu_per_cyc\":%.6f,\"cpi_per_cyc\":%.6f,\"exc_per_cyc\":%.6f,\"fold_per_cyc\":%.6f}",
            s.device_id, s.window_id, s.label,
            s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
            s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc
        );

        sent++;
        if (pos > (int)sizeof(out) - 220) break;
    }

    pos += snprintf(out + pos, sizeof(out) - pos,
        "],\"from\":%u,\"to\":%u,\"count\":%d}\n",
        sent ? first_id : 0,
        sent ? last_id : 0,
        sent
    );

    comm_send_str(out);
    return;
}
    if (strstr(line, "\"type\":\"ATTEST_REQUEST\"")) {
    char req_id2[64];
    extract_req_id(line, req_id2, (int)sizeof(req_id2));

    // --- parse nonce hex ---
    // Expect: "nonce":"<hex>"
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
    memcpy(nonce_hex, pn, nhex);
    nonce_hex[nhex] = 0;

    // hex -> bytes
    // very small hex decode
    uint8_t nonce[64];
    size_t nonce_len = 0;
    for (int i = 0; i + 1 < nhex && nonce_len < sizeof(nonce); i += 2) {
        char a = nonce_hex[i], b = nonce_hex[i+1];
        uint8_t hi = (a <= '9') ? (a - '0') : ((a | 32) - 'a' + 10);
        uint8_t lo = (b <= '9') ? (b - '0') : ((b | 32) - 'a' + 10);
        nonce[nonce_len++] = (hi << 4) | lo;
    }

    // compute fw hash + nonce-bound response
    uint8_t fw_hash[32], resp[32];
    compute_fw_hash(fw_hash);
    compute_nonce_bound_response(nonce, nonce_len, fw_hash, resp);

    char fw_hex[65], resp_hex[65];
    to_hex(fw_hash, 32, fw_hex);
    to_hex(resp, 32, resp_hex);

    // Send ATTEST_RESPONSE (includes fw_hash_hex so verifier can provision)
    char out[420];
    snprintf(out, sizeof(out),
        "{\"type\":\"ATTEST_RESPONSE\",\"req_id\":\"%s\",\"mode\":\"FULL_HASH_PROVER\",\"region\":\"fw\","
        "\"fw_hash_hex\":\"%s\",\"response_hex\":\"%s\"}\n",
        req_id2[0] ? req_id2 : "none", fw_hex, resp_hex);

    comm_send_str(out);
    return;
}

    char out[220];
    snprintf(out, sizeof(out),
             "{\"type\":\"ERROR\",\"req_id\":\"%s\",\"reason\":\"unknown_request\"}\n",
             req_id[0] ? req_id : "none");
    comm_send_str(out);
}

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
    memmove(rxbuf, start, remaining);
    rxlen = remaining;
}

// lwIP recv callback: just append bytes, parse later in main loop
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)arg;
    if (!p) {
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
    g_connected = false;
    g_pcb = NULL;
}

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK) return err;

    g_connected = true;
    g_pcb = tpcb;

    // Send HELLO
    char hello[128];
    snprintf(hello, sizeof(hello),
             "{\"type\":\"HELLO\",\"device_id\":\"pico2w_%u\"}\n", DEVICE_ID);
    comm_send_str(hello);

    return ERR_OK;
}

static bool comm_connect_wifi_tcp(void) {
    if (cyw43_arch_init()) {
        printf("cyw43_arch_init failed\n");
        return false;
    }
    cyw43_arch_enable_sta_mode();

    // NOTE: επειδή έχεις spaces στο SSID, για αρχή hardcode εδώ για να μην σε σκοτώνουν τα quotes του CMake:
    const char *ssid = "Get your own";
    const char *pass = "igataeinaiteleia";

    printf("Connecting WiFi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(ssid, pass, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("WiFi connect FAILED\n");
        return false;
    }
    printf("WiFi OK\n");

    printf("VERIFIER_IP=%s PORT=%d\n", VERIFIER_IP, VERIFIER_PORT);

ip4_addr_t myip = *netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_STA]);
printf("Pico IP: %s\n", ip4addr_ntoa(&myip));

    ip4_addr_t addr;
int ok = ip4addr_aton(VERIFIER_IP, &addr);
printf("ip4addr_aton ok=%d\n", ok);

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
        printf("tcp_connect failed: %d\n", (int)e);
        return false;
    }

    return true;
}

// ===================== main =====================
int main(void) {
    stdio_init_all();
    //wait_for_usb_connection();
    dwt_enable_all();
comm_connect_wifi_tcp();



    // init prevs
    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    //printf("device_id,window_id,label,dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    // timers
    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    const uint32_t windows_per_class = 300;

    for (int phase = 0; phase < 3; phase++) {
        current_label = (uint32_t)phase;
        uint32_t end_window = window_id + windows_per_class;

        while (1) {
            // keep CPU doing the workload; timers sample in background
            cyw43_arch_poll();
            run_workload_step((int)current_label);
            comm_poll_parse();

            // print ready samples from ring (SAFE in main)
           /* sample_t s;
            while (ring_pop(&s)) {
                printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                       s.device_id, s.window_id, s.label,
                       s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
                       s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
            }
                       */
        }
    }

    // drain
    /*sample_t s;
    while (ring_pop(&s)) {
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s.device_id, s.window_id, s.label,
               s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
               s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
    }*/

   // cancel_repeating_timer(&t2ms);
   // cancel_repeating_timer(&t100ms);

   // printf("DONE\n");
    while (1) sleep_ms(1000);
}
