//old experiment with code injection that prints 

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/sync.h"

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

#define DEVICE_ID 1
static volatile uint32_t do_payload_once = 0;

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

static inline void dwt_reset_event_counters(void) {
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

// ===================== "Payload engine" (dormant unless enabled by FLASH config) =====================
typedef enum {
    PAY_NONE     = 0,
    PAY_MEMSCAN  = 1, // LSU-heavy
    PAY_BRANCH   = 2, // control-flow heavy
    PAY_ALU      = 3  // compute-heavy
} pattern_t;

// --------------------- ATTTESTED CONFIG (lives in FLASH) ---------------------
// Αυτό είναι το “κουμπί” που θα πατσάρεις στη flash.
// Αν ο verifier κάνει hash το block που το περιέχει => hash mismatch.
// Και επειδή αυτό ενεργοποιεί/ρυθμίζει payload => counters αλλάζουν έντονα.

typedef struct __attribute__((packed)) {
    uint32_t magic;       // 0xC0FFEE00
    uint32_t enabled;     // 0/1
    uint32_t pattern_id;  // PAY_*
    uint32_t intensity;   // 1..64
    uint32_t size_bytes;  // for memscan
} inj_cfg_t;

// NOTE: διάλεξε alignment ίσο με το attestation block size σου (π.χ. 256 ή 4096)
#ifndef ATTEST_BLOCK_ALIGN
#define ATTEST_BLOCK_ALIGN 256
#endif

__attribute__((section(".attested_cfg"), used, aligned(ATTEST_BLOCK_ALIGN)))
volatile const inj_cfg_t g_inj_cfg = {
    .magic      = 0xC0FFEE00u,
    .enabled    = 0u,
    .pattern_id = PAY_NONE,
    .intensity  = 0u,
    .size_bytes = 0u,
};

static inline volatile const inj_cfg_t* inj_cfg(void) {
    return &g_inj_cfg;
}


static inline bool inj_enabled(void) {
    volatile const inj_cfg_t *c = inj_cfg();

    return (c->magic == 0xC0FFEE00u) && (c->enabled != 0u);
}

// Sandbox buffer (data-only)
#define SANDBOX_BYTES (16 * 1024)
static uint8_t sandbox[SANDBOX_BYTES];

// fast-ish PRNG step
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

// Payload A: memory scan / xor (hits dL / LSU)
static inline void payload_memscan(uint32_t size_bytes, uint32_t intensity) {
    if (intensity == 0) return;
    size_bytes = clamp_u32(size_bytes, 64u, SANDBOX_BYTES);

    uint32_t x = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;

    for (uint32_t pass = 0; pass < intensity; pass++) {
        uint32_t stride = 1u + ((x >> 5) & 0x7Fu); // 1..64
        for (uint32_t i = 0; i < size_bytes; i += stride) {
            x = xs32(x + i + pass);
            sandbox[i] ^= (uint8_t)x;
        }
        x = xs32(x + 0x9E3779B9u);
    }

    __asm volatile("" ::: "memory");
}

// Payload B: branch/obfuscation storm (hits CPI / cycles)
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

// Payload C: compute-heavy "crypto-ish" mixing (hits cycles cleanly)
static inline uint32_t payload_alu(uint32_t iters) {
    if (iters < 1000u) iters = 1000u;

    uint32_t x = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;
    uint32_t s = 0x12345678u;

    for (uint32_t i = 0; i < iters; i++) {
        x = xs32(x + i);
        s ^= rotl32(x, (x & 7u) + 1u);
        s += 0x9E3779B9u;
        s ^= (s >> 16);
        s *= 0x85EBCA6Bu;
        s ^= (s >> 13);
    }

    __asm volatile("" ::: "memory");
    return s;
}

// Run selected payload
static volatile uint32_t payload_sink = 0;
static inline void injected_payload_step(pattern_t pat, uint32_t size_bytes, uint32_t intensity) {
    if (pat == PAY_MEMSCAN) {
        payload_memscan(size_bytes, intensity);
    } else if (pat == PAY_BRANCH) {
        uint32_t iters = clamp_u32(intensity, 1u, 64u) * 2500u; // 2.5k..160k
        payload_sink ^= payload_branchstorm(iters);
    } else if (pat == PAY_ALU) {
        uint32_t iters = clamp_u32(intensity, 1u, 64u) * 4000u; // 4k..256k
        payload_sink ^= payload_alu(iters);
    } else {
        // none
    }
}

// ===================== Labels / bucket control =====================
// workload 0/1/2
static volatile uint32_t current_workload = 0;
static volatile uint32_t bucket_id_g = 0;
static volatile uint32_t window_id_g = 0;
static volatile uint32_t run_id_g = 0;

// leaf_label mapping:
// safe: 0/1/2 (workload)
// compromised: 4
static inline uint32_t compute_leaf_label_from_cfg(void) {
    return inj_enabled() ? 4u : current_workload;
}

static inline uint32_t compute_attack_type_from_cfg(void) {
    return inj_enabled() ? 2u : 0u; // 2 = compromised (schema reuse)
}

static inline uint32_t compute_attack_level_from_cfg(void) {
    return inj_enabled() ? inj_cfg()->intensity : 0u;
}

static inline uint32_t compute_pattern_id_from_cfg(void) {
    return inj_enabled() ? inj_cfg()->pattern_id : (uint32_t)PAY_NONE;
}

static inline uint32_t compute_size_bytes_from_cfg(void) {
    return inj_enabled() ? inj_cfg()->size_bytes : 0u;
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

static volatile agg_t agg = {0};

static uint32_t prev_cyc = 0;
static uint64_t prev_t_us = 0;

static uint8_t prev_lsu8 = 0, prev_cpi8 = 0, prev_exc8 = 0, prev_fold8 = 0, prev_sleep8 = 0;

static inline uint8_t delta_u8(uint8_t curr, uint8_t prev) {
    return (uint8_t)(curr - prev);
}

// ===================== Sample struct + ring buffer =====================
typedef struct {
    uint32_t run_id;
    uint32_t device_id;
    uint32_t bucket_id;
    uint32_t window_id;

    uint32_t workload;       // 0/1/2
    uint32_t attack_type;    // 0 none, 2 compromised
    uint32_t attack_level;   // intensity
    uint32_t compromised;    // 0/1
    uint32_t leaf_label;     // 0..2 safe, 4 compromised

    uint32_t pattern_id;     // PAY_*
    uint32_t size_bytes;     // payload size

    uint32_t dC, dL, dP, dE, dF, dS, dT;

    float cyc_per_us;
    float lsu_per_cyc;
    float cpi_per_cyc;
    float exc_per_cyc;
    float fold_per_cyc;
} sample_t;

#define RING_N 256
static sample_t ring[RING_N];
static volatile uint32_t w_idx = 0;
static volatile uint32_t r_idx = 0;

static inline bool ring_push(const sample_t *s) {
    uint32_t irq = save_and_disable_interrupts();
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) {
        restore_interrupts(irq);
        return false;
    }
    ring[w_idx] = *s;
    w_idx = next;
    restore_interrupts(irq);
    return true;
}

static inline bool ring_pop(sample_t *out) {
    uint32_t irq = save_and_disable_interrupts();
    if (r_idx == w_idx) {
        restore_interrupts(irq);
        return false;
    }
    *out = ring[r_idx];
    r_idx = (r_idx + 1u) % RING_N;
    restore_interrupts(irq);
    return true;
}

static inline void ring_reset(void) {
    uint32_t irq = save_and_disable_interrupts();
    w_idx = r_idx = 0;
    restore_interrupts(irq);
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

// ===================== 100ms callback: one sample =====================
bool timer_100ms_cb(struct repeating_timer *t) {
    (void)t;

    agg_t a;
    uint32_t irq = save_and_disable_interrupts();
    a = agg;
    agg = (agg_t){0};
    restore_interrupts(irq);

    float fdT = (a.sum_dt_us > 0) ? (float)a.sum_dt_us : 1.0f;
    float fdC = (a.sum_cyc   > 0) ? (float)a.sum_cyc   : 1.0f;

    sample_t s = {0};
    s.run_id    = run_id_g;
    s.device_id = DEVICE_ID;
    s.bucket_id = bucket_id_g;
    s.window_id = window_id_g++;

    // Labels derived from FLASH config (this is the point)
    volatile const inj_cfg_t *c = inj_cfg();

    bool comp = (c->magic == 0xC0FFEE00u) && (c->enabled != 0u);

    s.workload     = current_workload;
    s.attack_type  = comp ? 2u : 0u;
    s.attack_level = comp ? c->intensity : 0u;
    s.compromised  = comp ? 1u : 0u;
    s.leaf_label   = comp ? 4u : current_workload;

    s.pattern_id  = comp ? c->pattern_id : (uint32_t)PAY_NONE;
    s.size_bytes  = comp ? c->size_bytes : 0u;

    s.dT = a.sum_dt_us;
    s.dC = a.sum_cyc;
    s.dL = a.sum_lsu;
    s.dP = a.sum_cpi;
    s.dE = a.sum_exc;
    s.dF = a.sum_fold;
    s.dS = a.sum_sleep;

    s.cyc_per_us   = ((float)a.sum_cyc)  / fdT;
    s.lsu_per_cyc  = ((float)a.sum_lsu)  / fdC;
    s.cpi_per_cyc  = ((float)a.sum_cpi)  / fdC;
    s.exc_per_cyc  = ((float)a.sum_exc)  / fdC;
    s.fold_per_cyc = ((float)a.sum_fold) / fdC;


    do_payload_once = 1;
    (void)ring_push(&s);
    return true;
}

// ===================== Timer control =====================
static struct repeating_timer t2ms;
static struct repeating_timer t100ms;
static bool timers_running = false;

static void start_timers(void) {
    if (timers_running) return;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);
    timers_running = true;
}

static void stop_timers(void) {
    if (!timers_running) return;
    cancel_repeating_timer(&t2ms);
    cancel_repeating_timer(&t100ms);
    timers_running = false;
}

static inline bool take_do_payload_once(void) {
    uint32_t irq = save_and_disable_interrupts();
    bool ok = (do_payload_once != 0);
    if (ok) do_payload_once = 0;
    restore_interrupts(irq);
    return ok;
}

static void reset_sampling_state(void) {
    uint32_t irq = save_and_disable_interrupts();
    agg = (agg_t){0};
    restore_interrupts(irq);

    ring_reset();
    dwt_reset_event_counters();

    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;
}

// ===================== Collection (no printf while collecting) =====================
#define SAMPLES_PER_BUCKET 150
static sample_t bucket_buf[SAMPLES_PER_BUCKET];

// IMPORTANT: keep header and row printing consistent (23 columns)
static void dump_bucket(const sample_t *buf, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        const sample_t *s = &buf[i];
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s->run_id, s->device_id, s->bucket_id, s->window_id,
               s->workload, s->attack_type, s->attack_level, s->compromised, s->leaf_label,
               s->pattern_id, s->size_bytes,
               s->dC, s->dL, s->dP, s->dE, s->dF, s->dS, s->dT,
               s->cyc_per_us, s->lsu_per_cyc, s->cpi_per_cyc, s->exc_per_cyc, s->fold_per_cyc);
    }
}

// Run baseline workload step + optional "payload" controlled by FLASH config
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

    // ---- "pseudo-injection": governed by FLASH config bytes (attested) ----
    volatile const inj_cfg_t *c = inj_cfg();
    if ((c->magic == 0xC0FFEE00u) && (c->enabled != 0u) && take_do_payload_once()) {
        do_payload_once = 0;

        uint32_t pat = c->pattern_id;
        if (pat > PAY_ALU) pat = PAY_NONE;

        uint32_t intensity = clamp_u32(c->intensity, 1u, 64u);     // τώρα μπορείς να σηκώσεις clamp
        uint32_t size_bytes = clamp_u32(c->size_bytes, 64u, SANDBOX_BYTES);

        injected_payload_step((pattern_t)pat, size_bytes, intensity);
    }



    if (current_workload == 0) sleep_ms(2);
}

static void collect_exact_samples(uint32_t target_n) {
    uint32_t collected = 0;
    while (collected < target_n) {
        run_one_step();

        sample_t s;
        while (collected < target_n && ring_pop(&s)) {
            bucket_buf[collected++] = s;
        }
    }
}

// Collect one bucket for a workload and dump CSV
static void run_bucket(uint32_t workload, uint32_t n_samples) {
    current_workload = workload;

    collect_exact_samples(n_samples);

    stop_timers();
    dump_bucket(bucket_buf, n_samples);
    sleep_ms(100); 

    reset_sampling_state();
    start_timers();
}

// ===================== main =====================
int main(void) {
    stdio_init_all();


    wait_for_usb_connection();

    volatile const inj_cfg_t *c0 = inj_cfg();
printf("# cfg magic=%08x enabled=%u pattern=%u intensity=%u size=%u\n",
       (unsigned)c0->magic,
       (unsigned)c0->enabled,
       (unsigned)c0->pattern_id,
       (unsigned)c0->intensity,
       (unsigned)c0->size_bytes);

    srand((unsigned)time_us_64());
    const uint8_t *p = (const uint8_t *)c0;

printf("# cfg bytes: ");
for (int i = 0; i < 20; i++) printf("%02x", p[i]);
printf("\n");

    // init sandbox
    for (uint32_t i = 0; i < SANDBOX_BYTES; i++) sandbox[i] = (uint8_t)(0xA5u ^ (i & 0xFFu));

    dwt_enable_all();
    reset_sampling_state();

    run_id_g = (uint32_t)(time_us_64() & 0xFFFFu);

    // helpful metadata
    printf("# attested_cfg_addr=0x%08x size=%u align=%u\n",
           (unsigned)(uintptr_t)&g_inj_cfg,
           (unsigned)sizeof(g_inj_cfg),
           (unsigned)ATTEST_BLOCK_ALIGN);

    // CSV header (23 cols) — MUST match dump_bucket()
    printf("run_id,device_id,bucket_id,window_id,workload,attack_type,attack_level,compromised,leaf_label,pattern_id,size_bytes,"
           "dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    start_timers();

    // Continuous collection: round-robin workloads.
    // Για SAFE firmware: g_inj_cfg.enabled=0 => no payload => normal counters.
    // Για COMPROMISED firmware: patch g_inj_cfg.* στη flash => payload ON => counters anomaly.
    while (1) {
        for (uint32_t wl = 0; wl < 3; wl++) {
            bucket_id_g++;
            run_bucket(wl, SAMPLES_PER_BUCKET);
        }
    }
}
