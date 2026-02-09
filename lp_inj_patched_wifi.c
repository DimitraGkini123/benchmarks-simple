// ============================================================
// Pico 2W: Workload windows (DWT) + pseudo-injection via FLASH cfg
//        + WiFi/TCP JSON protocol (PING / GET_WINDOWS / ATTEST_REQUEST)
//
// NEW: Delayed enable after 20s by flipping one FLASH bit (1->0).
//      No UF2 patching needed. Safe hash matches until enable time.
//      Enable is performed in main loop with measurement gating,
//      so net_service + enable action won't pollute counters.


//MEMSCAN + ALU
// ============================================================

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "pico/stdlib.h"
#include "pico/time.h"
#include "hardware/timer.h"
#include "hardware/sync.h"
#include "hardware/flash.h"
#include "hardware/regs/addressmap.h" // XIP_BASE

// WiFi / lwIP
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"

// SHA256 (as in your existing project)
#include "sha256.h"

// ===================== Device / Verifier =====================
#define DEVICE_ID 1

#ifndef VERIFIER_IP
#define VERIFIER_IP "192.168.68.102"
#endif
#ifndef VERIFIER_PORT
#define VERIFIER_PORT 4242
#endif

// ------- Partial attestation config -------
#define FW_BLOCKS_N    128
#define MAX_REQ_BLOCKS 32

// linker symbols provided by Pico toolchain
extern const uint8_t __flash_binary_start;
extern const uint8_t __flash_binary_end;

// ===================== DWT registers (Cortex-M33 / Pico 2W) =====================
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

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif


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

static inline void dwt_reset_event_counters_only(void) {
    DWT_CYCCNT   = 0;
    DWT_CPICNT   = 0;
    DWT_EXCCNT   = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT   = 0;
    DWT_FOLDCNT  = 0;
}

static void wait_for_usb_connection(void) {
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(200);
}

// ===================== Signal pipeline (baseline workload) =====================
#define LEN 512
static double sig_in[LEN];
static double sig_filt[LEN];

#define LPF_ORDER 8
static const double lp_coefficients[LPF_ORDER] = {
    -0.00511, 0.01017, 0.05730, 0.20164,
     0.47291, 0.20164, 0.05730, 0.01017
};

static void generate_signal(double fs, int workload_label) {
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);

    double tremor_f   = (workload_label==0) ? 4.0 : (workload_label==1 ? 5.5 : 7.5);
    double tremor_amp = (workload_label==0) ? 0.08 : (workload_label==1 ? 0.25 : 0.50);
    double noise_amp  = (workload_label==0) ? 0.02 : (workload_label==1 ? 0.03 : 0.06);

    tremor_f   += ((rand()%100)/200.0);
    tremor_amp += ((rand()%100)/1000.0);

    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * f_ecg * t);
        double tremor = tremor_amp * sin(2 * M_PI * tremor_f * t);
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

// ===================== "Payload engine" (controlled by FLASH cfg bytes) =====================
typedef enum {
    PAY_NONE     = 0,
    PAY_MEMSCAN  = 1, // LSU-heavy
    PAY_BRANCH   = 2, // control-flow heavy
    PAY_ALU      = 3  // compute-heavy
} pattern_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;       // 0xC0FFEE00
    uint32_t enabled;     // ACTIVE-LOW: bit0=1 => OFF, bit0=0 => ON (flash 1->0)
    uint32_t pattern_id;  // PAY_*
    uint32_t intensity;   // 1..64
    uint32_t size_bytes;  // for memscan
} inj_cfg_t;

#ifndef ATTEST_BLOCK_ALIGN
#define ATTEST_BLOCK_ALIGN 256
#endif

// IMPORTANT: safe image has injection DISABLED initially.
// enabled=0xFFFFFFFF => bit0=1 => OFF.
// After 20s we will clear bit0 => 0xFE => ON.
__attribute__((section(".attested_cfg"), used, aligned(ATTEST_BLOCK_ALIGN)))
volatile const inj_cfg_t g_inj_cfg = {
    .magic      = 0xC0FFEE00u,
    .enabled    = 0xFFFFFFFFu,   // OFF (active-low)
    //.enabled = 0xFFFFFFFEu,   // bit0=0 => ON
    .pattern_id = PAY_ALU,   // preloaded
    .intensity  = 64u,           // preloaded
    .size_bytes = 4096u,         // preloaded
};

static inline volatile const inj_cfg_t* inj_cfg(void) {
    return &g_inj_cfg;
}

static inline bool inj_enabled(void) {
    volatile const inj_cfg_t *c = inj_cfg();
    if (c->magic != 0xC0FFEE00u) return false;
    return ((c->enabled & 1u) == 0u); // ACTIVE-LOW enable
}

#define SANDBOX_BYTES (16 * 1024)
static uint8_t sandbox[SANDBOX_BYTES];

static inline uint32_t xs32(uint32_t x){
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return x;
}

static inline uint32_t clamp_u32(uint32_t x, uint32_t lo, uint32_t hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

static inline uint32_t rotl32(uint32_t x, uint32_t r){
    return (x << r) | (x >> (32u - r));
}
//lots of memory loads/stores
//made sandbox --> buffer in ram  , dummy memory so i can access it and leave footprint
static inline void payload_memscan(uint32_t size_bytes, uint32_t intensity) {
    if (intensity == 0) return;
    size_bytes = clamp_u32(size_bytes, 64u, SANDBOX_BYTES);

    uint32_t x = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;

    for (uint32_t pass = 0; pass < intensity; pass++) {
        uint32_t stride = 1u + ((x >> 5) & 0x7Fu); // 1..128
        for (uint32_t i = 0; i < size_bytes; i += stride) {
            x = xs32(x + i + pass);
            sandbox[i] ^= (uint8_t)x;
        }
        x = xs32(x + 0x9E3779B9u);
    }

    __asm volatile("" ::: "memory");
}

static inline uint32_t payload_branchstorm(uint32_t iters) {
    if (iters < 500u) iters = 500u;

    uint32_t x = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;
    uint32_t acc = 0;

    for (uint32_t i = 0; i < iters; i++) {
        x = xs32(x + i);
        switch (x & 7u) {
            case 0: acc += (x ^ (x >> 3)); break;
            case 1: acc ^= (x + 0x9E37u); break;
            case 2: acc += (x * 33u); break;
            case 3: acc ^= (x * 17u); break;
            case 4: acc += (x << 1); break;
            case 5: acc ^= (x >> 1); break;
            case 6: acc += (x ^ 0xA5A5u); break;
            default: acc ^= (x ^ 0x5A5Au); break;
        }
    }

    __asm volatile("" ::: "memory");
    return acc;
}
//compute heavy 
static inline uint32_t payload_alu(uint32_t iters) {
    if (iters < 1000u) iters = 1000u;

    uint32_t x = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;
    uint32_t s = 0x12345678u;

    for (uint32_t i = 0; i < iters; i++) {
        x = xs32(x + i); //xor + shift
        s ^= rotl32(x, (x & 7u) + 1u);
        s += 0x9E3779B9u;
        s ^= (s >> 16);
        s *= 0x85EBCA6Bu;
        s ^= (s >> 13);
    }

    __asm volatile("" ::: "memory");
    return s;
}

static volatile uint32_t payload_sink = 0;
static inline void injected_payload_step(pattern_t pat, uint32_t size_bytes, uint32_t intensity) {
    if (pat == PAY_MEMSCAN) {
        payload_memscan(size_bytes, intensity);
    } else if (pat == PAY_BRANCH) {
        uint32_t iters = clamp_u32(intensity, 1u, 64u) * 2500u;
        payload_sink ^= payload_branchstorm(iters);
    } else if (pat == PAY_ALU) {
        uint32_t iters = clamp_u32(intensity, 1u, 64u) * 4000u;
        payload_sink ^= payload_alu(iters);
    }
}

// ===================== Workload / label mapping =====================
static volatile uint32_t current_workload = 0;
static volatile uint32_t window_id_g = 0;

// Run payload ONCE per 100ms sample
static volatile uint32_t do_payload_once = 0;
static inline bool take_do_payload_once(void) {
    uint32_t irq = save_and_disable_interrupts();
    bool ok = (do_payload_once != 0);
    if (ok) do_payload_once = 0;
    restore_interrupts(irq);
    return ok;
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

// prev readings for delta
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

    uint32_t workload;       // 0/1/2
    uint32_t compromised;    // 0/1
    uint32_t leaf_label;     // 0..2 safe, 4 compromised

    uint32_t pattern_id;     // PAY_*
    uint32_t size_bytes;     // payload size
    uint32_t intensity;      // intensity

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

static inline bool ring_push_isr_safe(const sample_t *s) {
    uint32_t flags = save_and_disable_interrupts();
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) {
        ring_dropped++;
        restore_interrupts(flags);
        return false;
    }
    ring[w_idx] = *s;
    w_idx = next;
    restore_interrupts(flags);
    return true;
}

// ===================== Measurement gating: make net + enable "invisible" =====================
static inline void measurement_pause_for_side_effect(void) {
    uint32_t flags = save_and_disable_interrupts();
    agg = (agg_t){0};
    restore_interrupts(flags);

    dwt_reset_event_counters_only();

    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;
}

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

    agg_t a;
    uint32_t flags = save_and_disable_interrupts();
    a = agg;
    agg = (agg_t){0};
    restore_interrupts(flags);

    float fdT = (a.sum_dt_us > 0) ? (float)a.sum_dt_us : 1.0f;
    float fdC = (a.sum_cyc   > 0) ? (float)a.sum_cyc   : 1.0f;

    volatile const inj_cfg_t *c = inj_cfg();
    bool comp = inj_enabled();

    sample_t s = (sample_t){0};
    s.device_id = DEVICE_ID;
    s.window_id = window_id_g++;

    s.workload    = current_workload;
    s.compromised = comp ? 1u : 0u;
    s.leaf_label  = comp ? 4u : current_workload;

    s.pattern_id = comp ? c->pattern_id : (uint32_t)PAY_NONE;
    s.size_bytes = comp ? c->size_bytes : 0u;
    s.intensity  = comp ? c->intensity  : 0u;

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

    do_payload_once = 1;
    (void)ring_push_isr_safe(&s);
    return true;
}

// ===================== SHA helpers (ATTTESTATION) =====================
static void to_hex(const uint8_t *in, size_t n, char *out_hex) {
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

// ===================== WiFi/TCP comms =====================
static struct tcp_pcb *g_pcb = NULL;
static bool g_connected = false;

static char rxbuf[2048];
static int  rxlen = 0;
static volatile bool rx_dirty = false;

static char txbuf_windows[24000];
static char txbuf_attest[16000];

static bool wifi_ready = false;
static absolute_time_t next_reconnect_at;

// forward declarations
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

        g_connected = false;
        g_pcb = NULL;
        return false;
    }

    return true;
}

static void comm_send_str(const char *s) {
    (void)comm_send_all(s, strlen(s));
}

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

// ===================== parse buffered rx =====================
static void handle_line(char *line) {
    char req_id[64];
    extract_req_id(line, req_id, (int)sizeof(req_id));

    if (strstr(line, "\"type\":\"PING\"")) {
        char out[160];
        snprintf(out, sizeof(out), "{\"type\":\"PONG\",\"req_id\":\"%s\"}\n", req_id);
        measurement_pause_for_side_effect();
        comm_send_str(out);
        measurement_pause_for_side_effect();
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
                "{"
                "\"window_id\":%u,"
                "\"label\":%u,"
                "\"dC\":%u,\"dL\":%u,\"dP\":%u,\"dE\":%u,\"dF\":%u,\"dS\":%u,\"dT\":%u,"
                "\"cyc_per_us\":%.6f"
                "}",
                (unsigned)s.window_id,
                (unsigned)s.leaf_label,
                (unsigned)s.dC, (unsigned)s.dL, (unsigned)s.dP, (unsigned)s.dE,
                (unsigned)s.dF, (unsigned)s.dS, (unsigned)s.dT,
                (double)s.cyc_per_us
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

        measurement_pause_for_side_effect();
        bool ok = comm_send_all(out, (size_t)pos);
        measurement_pause_for_side_effect();

        if (ok) {
            uint32_t f = save_and_disable_interrupts();
            while (r_idx != w_idx) {
                sample_t cur = ring[r_idx];
                if (cur.window_id <= since) r_idx = (r_idx + 1u) % RING_N;
                else break;
            }
            if (sent > 0) {
                while (r_idx != w_idx) {
                    sample_t cur = ring[r_idx];
                    if (cur.window_id <= last_id) r_idx = (r_idx + 1u) % RING_N;
                    else break;
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

                char bh_hex[65], resp_hex[65];
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

            measurement_pause_for_side_effect();
            comm_send_str(out);
            measurement_pause_for_side_effect();
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

            measurement_pause_for_side_effect();
            comm_send_str(out);
            measurement_pause_for_side_effect();
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

static inline void net_service(void) {
    cyw43_arch_poll();
    comm_poll_parse();
    comm_ensure_connected();
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
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

    char hello[200];
    snprintf(hello, sizeof(hello),
         "{\"type\":\"HELLO\",\"device_id\":\"pico2w_%u\",\"fw_blocks_n\":%u,\"max_req_blocks\":%u}\n",
         DEVICE_ID, (unsigned)FW_BLOCKS_N, (unsigned)MAX_REQ_BLOCKS);

    measurement_pause_for_side_effect();
    comm_send_str(hello);
    measurement_pause_for_side_effect();

    return ERR_OK;
}

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

static void comm_tcp_close(void) {
    if (!g_pcb) return;

    cyw43_arch_lwip_begin();
    tcp_arg(g_pcb, NULL);
    tcp_recv(g_pcb, NULL);
    tcp_err(g_pcb, NULL);
    tcp_abort(g_pcb);
    cyw43_arch_lwip_end();

    g_pcb = NULL;
    g_connected = false;
}

static bool comm_tcp_connect(void) {
    if (!wifi_ready) return false;

    ip4_addr_t addr;
    int ok = ip4addr_aton(VERIFIER_IP, &addr);
    printf("ip4addr_aton ok=%d\n", ok);
    if (!ok) return false;

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

static void comm_ensure_connected(void) {
    if (g_connected && g_pcb) return;

    if (!time_reached(next_reconnect_at)) return;
    next_reconnect_at = make_timeout_time_ms(2000);

    if (!comm_wifi_init_once()) return;

    measurement_pause_for_side_effect();
    (void)comm_tcp_connect();
    measurement_pause_for_side_effect();
}

// ===================== rate-limited gated net service =====================
static absolute_time_t next_net_at;
static inline void net_service_gated_rl(void) {
    if (!time_reached(next_net_at)) return;
    next_net_at = make_timeout_time_ms(10);

    measurement_pause_for_side_effect();
    net_service();
    measurement_pause_for_side_effect();
}

// ===================== FLASH: patch 1 byte (1->0 only) =====================
static void flash_patch_one_byte(const uint8_t *xip_addr, uint8_t new_val)
{
    uintptr_t a = (uintptr_t)xip_addr;
    uintptr_t page_base = a & ~(uintptr_t)(FLASH_PAGE_SIZE - 1);

    uint8_t buf[FLASH_PAGE_SIZE];
    memcpy(buf, (const void*)page_base, FLASH_PAGE_SIZE);

    size_t off = (size_t)(a - page_base);

    // Only 1->0
    buf[off] = (uint8_t)(buf[off] & new_val);

    uint32_t flash_off = (uint32_t)(page_base - (uintptr_t)XIP_BASE);

    uint32_t irq = save_and_disable_interrupts();
    flash_range_program(flash_off, buf, FLASH_PAGE_SIZE);
    restore_interrupts(irq);
}

// ===================== delayed enable (20s) =====================
static volatile uint32_t enable_due = 0;

static int64_t enable_alarm_cb(alarm_id_t id, void *user_data) {
    (void)id; (void)user_data;
    enable_due = 1; // do it in main loop (not ISR)
    return 0;
}

static void schedule_enable_after_30s(void) {
    add_alarm_in_ms(30000, enable_alarm_cb, NULL, false);
}

static void maybe_enable_injection_delayed(void) {
    if (!enable_due) return;

    // consume flag
    uint32_t f = save_and_disable_interrupts();
    bool do_it = (enable_due != 0);
    enable_due = 0;
    restore_interrupts(f);

    if (!do_it) return;

    // Make this side-effect invisible to counters
    measurement_pause_for_side_effect();

    // enabled field starts at +4 bytes; clear bit0 by programming 0xFE (11111110)
    const uint8_t *enabled_lsb = ((const uint8_t*)inj_cfg()) + 4;
    flash_patch_one_byte(enabled_lsb, 0xFE);

    measurement_pause_for_side_effect();

    // Print what we see now (raw + fields)
    const uint8_t *raw = (const uint8_t*)inj_cfg();
    printf(">> enabled after 30s; cfg @ %p\n", (void*)inj_cfg());
    printf(">> cfg raw 20B: ");
    for (int i = 0; i < 20; i++) printf("%02x", raw[i]);
    printf("\n");
    printf(">> cfg magic=%08x enabled=%08x pat=%u intensity=%u size=%u inj_enabled=%u\n",
        (unsigned)inj_cfg()->magic,
        (unsigned)inj_cfg()->enabled,
        (unsigned)inj_cfg()->pattern_id,
        (unsigned)inj_cfg()->intensity,
        (unsigned)inj_cfg()->size_bytes,
        (unsigned)inj_enabled()
    );
}

// ===================== Workload step (NO net_service inside) =====================
static inline void run_one_step(void) {
    const double fs = 250.0;

    generate_signal(fs, (int)current_workload);
    low_pass_fir(sig_in, sig_filt, LEN, lp_coefficients, LPF_ORDER);

    if (current_workload == 1) {
        low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    } else if (current_workload == 2) {
        for (int k = 0; k < 3; ++k) low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    }

    hr_sink += compute_hr(sig_filt, LEN, fs, 0.2);

    // pseudo-injection: governed by FLASH config bytes
    volatile const inj_cfg_t *c = inj_cfg();
    if (inj_enabled()) {
        uint32_t pat = c->pattern_id;
        if (pat > PAY_ALU) pat = PAY_NONE;

        uint32_t intensity = clamp_u32(c->intensity, 1u, 64u);
        uint32_t size_bytes = clamp_u32(c->size_bytes, 64u, SANDBOX_BYTES);

        injected_payload_step((pattern_t)pat, size_bytes, intensity);
    }

    if (current_workload == 0) sleep_ms(2);
}

// ===================== main =====================
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();

    // DEBUG at boot
    printf("cfg @ %p (XIP)\n", (void*)inj_cfg());
    const uint8_t *raw = (const uint8_t*)inj_cfg();
    printf("cfg raw 20B: ");
    for (int i = 0; i < 20; i++) printf("%02x", raw[i]);
    printf("\n");

    printf("# boot; cfg magic=%08x enabled=%08x pattern=%u intensity=%u size=%u inj_enabled=%u\n",
        (unsigned)inj_cfg()->magic,
        (unsigned)inj_cfg()->enabled,
        (unsigned)inj_cfg()->pattern_id,
        (unsigned)inj_cfg()->intensity,
        (unsigned)inj_cfg()->size_bytes,
        (unsigned)inj_enabled()
    );

    srand((unsigned)time_us_64());

    for (uint32_t i = 0; i < SANDBOX_BYTES; i++) sandbox[i] = (uint8_t)(0xA5u ^ (i & 0xFFu));

    dwt_enable_all();

    next_reconnect_at = make_timeout_time_ms(0);
    next_net_at = make_timeout_time_ms(0);

    (void)comm_wifi_init_once();

    measurement_pause_for_side_effect();
    (void)comm_tcp_connect();
    measurement_pause_for_side_effect();

    // init prevs for aggregator
    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;
    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    // Delayed enable
    schedule_enable_after_30s();

    absolute_time_t next_switch = make_timeout_time_ms(5000);

        while (1) {
            // keep stack alive but invisible to counters
            net_service_gated_rl();

            // after 20s, perform enable (invisible to counters)
            maybe_enable_injection_delayed();

            // compute-only work (counters reflect this)
            run_one_step();

            if (time_reached(next_switch)) {
                current_workload = (current_workload + 1u) % 3u;
                next_switch = make_timeout_time_ms(5000);
            }
        }
}
