#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

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
    // workload 0: light, 1: medium, 2: heavy
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

// ===================== Sandbox memory for ISR payload =====================
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

// ===================== Labels / bucket control =====================
typedef enum {
    PAT_NONE      = 0,
    PAT_INT_STORM = 1
} pattern_t;

static volatile uint32_t current_workload = 0;        // 0/1/2
static volatile uint32_t current_compromised = 0;     // 0 safe, 1 compromised
static volatile uint32_t current_attack_type = 0;     // 0 none, 2 = "INJ-like" (schema reuse)
static volatile uint32_t current_attack_level = 0;    // storm level
static volatile uint32_t current_leaf_label = 0;      // 0..2 safe workload, 4 compromised

static volatile uint32_t current_pattern_id = 0;      // 0 none, 1 storm
static volatile uint32_t current_size_bytes = 0;      // ISR payload bytes

static volatile uint32_t bucket_id_g = 0;
static volatile uint32_t window_id_g = 0;
static volatile uint32_t run_id_g = 0;

// leaf_label mapping:
// safe: 0/1/2 (workload)
// compromised (storm): 4
static inline uint32_t compute_leaf_label(void) {
    if (current_compromised == 0) return current_workload;
    return 4u;
}

// ===================== Interrupt Storm (benign ISR workload) =====================
static struct repeating_timer tstorm;
static volatile bool storm_running = false;

static volatile uint32_t storm_state = 0x12345678u;
static volatile uint32_t storm_sink  = 0;

// Map attack_level -> interrupt period in microseconds (smaller = more intense)
static inline int64_t storm_level_to_period_us(uint32_t level) {
    // 1: 500us (2 kHz), 2: 200us (5 kHz), 3: 100us (10 kHz), 4: 50us (20 kHz), 5: 25us (40 kHz)
    switch (level) {
        case 1: return 500;
        case 2: return 200;
        case 3: return 100;
        case 4: return 50;
        case 5: return 25;
        default: return 200;
    }
}

// This callback runs in IRQ context (alarm IRQ).
bool storm_cb(struct repeating_timer *t) {
    (void)t;

    uint32_t x = storm_state;
    x = xs32(x + 0x9E3779B9u);
    storm_state = x;

    // Use current_size_bytes as "ISR payload bytes"
    uint32_t bytes = clamp_u32(current_size_bytes, 16u, 2048u);

    // Touch scattered bytes in sandbox to generate LSU activity
    for (uint32_t i = 0; i < bytes; i += 16u) {
        uint32_t pos = (x + i * 33u) & (SANDBOX_BYTES - 1u); // 16k is power-of-two
        sandbox[pos] ^= (uint8_t)(x & 0xFFu);
        x = xs32(x + pos);
    }

    // Small branchy mix to perturb CPI a bit
    if (x & 1u) storm_sink += (x ^ (x << 3));
    else        storm_sink ^= (x + (x >> 2));

    return true;
}

static void storm_start(uint32_t level) {
    if (storm_running) return;
    int64_t period_us = storm_level_to_period_us(level);
    add_repeating_timer_us(-period_us, storm_cb, NULL, &tstorm);
    storm_running = true;
}

static void storm_stop(void) {
    if (!storm_running) return;
    cancel_repeating_timer(&tstorm);
    storm_running = false;
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
    uint32_t attack_type;    // 0 none, 2 compromised (schema-friendly)
    uint32_t attack_level;   // storm level
    uint32_t compromised;    // 0/1
    uint32_t leaf_label;     // 0..2 safe, 4 compromised

    uint32_t pattern_id;     // 0 none, 1 storm
    uint32_t size_bytes;     // ISR payload bytes

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

    s.workload     = current_workload;
    s.attack_type  = current_attack_type;
    s.attack_level = current_attack_level;
    s.compromised  = current_compromised;
    s.leaf_label   = compute_leaf_label();

    s.pattern_id  = current_pattern_id;
    s.size_bytes  = current_size_bytes;

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

static void reset_sampling_state(void) {
    storm_stop();

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

static void dump_bucket(const sample_t *buf, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        const sample_t *s = &buf[i];
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s->run_id, s->device_id, s->bucket_id, s->window_id,
               s->workload, s->attack_type, s->attack_level, s->compromised, s->leaf_label,
               s->pattern_id, s->size_bytes,
               s->dC, s->dL, s->dP, s->dE, s->dF, s->dS, s->dT,
               s->cyc_per_us, s->lsu_per_cyc, s->cpi_per_cyc, s->exc_per_cyc, s->fold_per_cyc);
    }
}

// Run baseline workload step (storm runs asynchronously if enabled)
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

static void run_bucket(uint32_t workload,
                       bool compromised,
                       pattern_t pat,
                       uint32_t isr_payload_bytes,
                       uint32_t storm_level,
                       uint32_t n_samples) {
    current_workload = workload;

    current_compromised  = compromised ? 1u : 0u;
    current_attack_type  = compromised ? 2u : 0u; // keep schema: 2 means "compromised"
    current_attack_level = compromised ? storm_level : 0u;

    current_pattern_id = (uint32_t)(compromised ? pat : PAT_NONE);
    current_size_bytes = (uint32_t)(compromised ? isr_payload_bytes : 0u);
    current_leaf_label = compute_leaf_label();

    if (current_compromised && pat == PAT_INT_STORM) {
        storm_state = (uint32_t)time_us_64() ^ (uint32_t)DWT_CYCCNT;
        storm_start(current_attack_level);
    }

    collect_exact_samples(n_samples);

    storm_stop();

    stop_timers();
    dump_bucket(bucket_buf, n_samples);

    reset_sampling_state();
    start_timers();
}

// ===================== main =====================
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();
    srand((unsigned)time_us_64());

    // init sandbox
    for (uint32_t i = 0; i < SANDBOX_BYTES; i++) sandbox[i] = (uint8_t)(0xA5u ^ (i & 0xFFu));

    dwt_enable_all();
    reset_sampling_state();

    run_id_g = (uint32_t)(time_us_64() & 0xFFFFu);

    // CSV header
    printf("run_id,device_id,bucket_id,window_id,workload,attack_type,attack_level,compromised,leaf_label,pattern_id,size_bytes,"
           "dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    start_timers();

    // ===================== Dataset design =====================
    // Θέλουμε 900 safe και 900 compromised.
    // Με SAMPLES_PER_BUCKET=150 => 6 buckets ανά κλάση.
    //
    // Safe: 2 buckets ανά workload (0/1/2) => 3*2=6 => 900
    // Compromised: 2 storm-configs ανά workload => 3*2=6 => 900

    const uint32_t SAFE_REPS = 2;

    typedef struct {
        pattern_t pat;
        uint32_t isr_payload_bytes; // stored in size_bytes
        uint32_t storm_level;       // stored in attack_level
    } attack_cfg_t;

    // 2 configs ώστε να έχεις ποικιλία footprint (freq + ISR payload)
    static const attack_cfg_t ATKS[2] = {
        { PAT_INT_STORM,  512, 3 },  // ~10kHz, moderate ISR work
        { PAT_INT_STORM, 1024, 4 }   // ~20kHz, heavier
    };
    const uint32_t NATK = 2;

    // SAFE (900)
    for (uint32_t rep = 0; rep < SAFE_REPS; rep++) {
        for (uint32_t wl = 0; wl < 3; wl++) {
            bucket_id_g++;
            run_bucket(wl, false, PAT_NONE, 0, 0, SAMPLES_PER_BUCKET);
        }
    }

    // COMPROMISED (900): interrupt storm
    for (uint32_t wl = 0; wl < 3; wl++) {
        for (uint32_t ai = 0; ai < NATK; ai++) {
            bucket_id_g++;
            run_bucket(wl, true,
                       ATKS[ai].pat,
                       ATKS[ai].isr_payload_bytes,
                       ATKS[ai].storm_level,
                       SAMPLES_PER_BUCKET);
        }
    }

    stop_timers();

    printf("# DONE\n");
    while (1) sleep_ms(1000);
}
