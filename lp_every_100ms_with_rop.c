#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/sync.h"

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

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ===================== Config =====================
#define DEVICE_ID 1

// Θέλεις περισσότερα SAFE → κάνε SAFE_REPEATS >= 6 για ισορροπία με attacks.
#define SAMPLES_PER_BUCKET 300
#define SAFE_REPEATS       6

// ===================== DWT helpers =====================
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

// ===================== Signal pipeline =====================
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

// ===================== Attack labels (synthetic anomalies) =====================
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_ROP  = 1,  // synthetic control-flow-ish + irregular memory access
    ATTACK_INJ  = 2,  // synthetic heavy writes
} attack_t;

static volatile attack_t  current_attack_type  = ATTACK_NONE;
static volatile uint32_t  current_attack_level = 0;   // 0/1/2
static volatile uint32_t  current_workload      = 0;  // 0/1/2

static inline uint32_t compromised_flag(void) {
    return (current_attack_type != ATTACK_NONE) ? 1u : 0u;
}

// Leaf label WITHOUT unknown:
// 0..2: SAFE workloads
// 3: ROP
// 4: INJ
static inline uint32_t leaf_label(uint32_t workload, uint32_t attack_type) {
    if (attack_type == ATTACK_NONE) return workload; // 0..2
    if (attack_type == ATTACK_ROP)  return 3u;
    return 4u; // ATTACK_INJ
}

// ===================== Small memory buffer to generate memory activity =====================
#define RW_BUF_N 4096
static uint32_t rw_buf[RW_BUF_N];

// ===================== Synthetic "ROP-like" anomaly =====================
__attribute__((noinline)) static uint32_t g1(uint32_t x){ return x * 1664525u + 1013904223u; }
__attribute__((noinline)) static uint32_t g2(uint32_t x){ return (x << 7) ^ (x >> 3) ^ 0xA5A5A5A5u; }
__attribute__((noinline)) static uint32_t g3(uint32_t x){ return (x + 0x9E3779B9u) ^ (x * 0x27d4eb2du); }
__attribute__((noinline)) static uint32_t g4(uint32_t x){ return (x ^ (x >> 16)) * 0x7feb352du; }
__attribute__((noinline)) static uint32_t g5(uint32_t x){ return (x ^ (x >> 15)) * 0x846ca68bu; }
__attribute__((noinline)) static uint32_t g6(uint32_t x){ return x ^ (x << 13) ^ (x >> 17) ^ (x << 5); }
__attribute__((noinline)) static uint32_t g7(uint32_t x){ return (x + 0x3c6ef372u) ^ (x >> 11); }
__attribute__((noinline)) static uint32_t g8(uint32_t x){ return (x * 0x85ebca6bu) ^ (x >> 13); }

typedef uint32_t (*gfn)(uint32_t);
static gfn chain[8] = { g1,g2,g3,g4,g5,g6,g7,g8 };

static inline void simulated_rop_anomaly(uint32_t level) {
    if (level == 0) return;

    uint32_t x = (uint32_t)DWT_CYCCNT ^ (uint32_t)time_us_64();
    int rounds = (level == 1) ? 24 : 48;

    for (int i = 0; i < rounds; i++) {
        x = chain[(x + (uint32_t)i) & 7u](x);
        if (x & 1u) x ^= 0xDEADBEEFu;
    }

    uint32_t acc = 0;
    int touches = (level == 1) ? 160 : 320;

    for (int i = 0; i < touches; i++) {
        uint32_t idx = (x ^ (uint32_t)i * 2654435761u) & (RW_BUF_N - 1u);
        rw_buf[idx] ^= (x + (uint32_t)i);
        acc ^= rw_buf[idx];
        x = g6(x + acc);
    }

    __asm volatile("" :: "r"(x), "r"(acc) : "memory");
}

// ===================== Synthetic "INJ-like" anomaly =====================
static inline void simulated_inj_anomaly(uint32_t level) {
    if (level == 0) return;

    uint32_t x = (uint32_t)time_us_64();
    int passes = (level == 1) ? 2 : 4;

    for (int p = 0; p < passes; p++) {
        for (uint32_t i = 0; i < RW_BUF_N; i += 4u) {
            rw_buf[i]     = (rw_buf[i]     + 0x11111111u) ^ x;
            rw_buf[i + 1] = (rw_buf[i + 1] + 0x22222222u) ^ (x >> 1);
            rw_buf[i + 2] = (rw_buf[i + 2] + 0x33333333u) ^ (x >> 2);
            rw_buf[i + 3] = (rw_buf[i + 3] + 0x44444444u) ^ (x >> 3);
            x = g1(x);
        }
        for (uint32_t i = 0; i + 16u < RW_BUF_N; i += 16u) {
            rw_buf[i + 8]  ^= rw_buf[i + 0];
            rw_buf[i + 9]  ^= rw_buf[i + 1];
            rw_buf[i + 10] ^= rw_buf[i + 2];
            rw_buf[i + 11] ^= rw_buf[i + 3];
        }
        x ^= rw_buf[(x & (RW_BUF_N - 1u))];
    }

    __asm volatile("" :: "r"(x) : "memory");
}

// ===================== Workload step =====================
static inline void run_workload_step(uint32_t workload_label) {
    const double fs = 250.0;

    if (workload_label == 0) generate_light_signal(fs);
    else if (workload_label == 1) generate_medium_signal(fs);
    else generate_heavy_signal(fs);

    // baseline filtering
    low_pass_fir(sig_in, sig_filt, LEN, lp_coefficients, LPF_ORDER);

    // workload-specific extra work
    if (workload_label == 1) {
        low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    } else if (workload_label == 2) {
        for (int k = 0; k < 3; ++k) low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
    }

    // SAFE variability (ώστε το "normal" να έχει ποικιλία)
    // μικρή πιθανότητα για extra FIR pass σε SAFE μόνο:
    if (current_attack_type == ATTACK_NONE) {
        if ((rand() % 10) == 0) { // 10% chance
            low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
        }
    }

    hr_sink += compute_hr(sig_filt, LEN, fs, 0.2);

    // anomaly work during attack
    if (current_attack_type == ATTACK_ROP) {
        simulated_rop_anomaly(current_attack_level);
    } else if (current_attack_type == ATTACK_INJ) {
        simulated_inj_anomaly(current_attack_level);
    }

    // LIGHT: jittered idle αντί για fixed sleep (μειώνει leakage/υπερ-εύκολη ταξινόμηση)
    if (workload_label == 0) {
        sleep_ms(1 + (rand() % 3)); // 1..3ms
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

static volatile agg_t agg = {0};

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

    // NEW: bucket id (για group split στο training)
    uint32_t bucket_id;

    // labels
    uint32_t workload;       // 0/1/2
    uint32_t attack_type;    // enum
    uint32_t attack_level;   // 0/1/2
    uint32_t compromised;    // 0/1

    // leaf label
    uint32_t leaf_label;     // 0..4

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
static sample_t ring[RING_N];
static volatile uint32_t w_idx = 0;
static volatile uint32_t r_idx = 0;
static volatile uint32_t dropped_ring_pushes = 0;

static inline bool ring_push(const sample_t *s) {
    uint32_t irq = save_and_disable_interrupts();
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) {
        dropped_ring_pushes++;
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

// ===================== Global ids =====================
static volatile uint32_t window_id_g = 0;
static volatile uint32_t bucket_id_g = 0;

// current bucket id (latched into samples)
static volatile uint32_t current_bucket_id = 0;

// ===================== 2ms callback: oversample DWT =====================
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

// ===================== 100ms callback: create one sample =====================
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
    s.device_id   = DEVICE_ID;
    s.window_id   = window_id_g++;
    s.bucket_id   = current_bucket_id;

    s.workload    = current_workload;
    s.attack_type = (uint32_t)current_attack_type;
    s.attack_level= current_attack_level;
    s.compromised = compromised_flag();
    s.leaf_label  = leaf_label(s.workload, s.attack_type);

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

// Reset sampling state so printing time doesn't contaminate next bucket
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

// ===================== Collection / Dump (NO printf during collection) =====================
static sample_t bucket_buf[SAMPLES_PER_BUCKET];

static void dump_bucket(const sample_t *buf, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        const sample_t *s = &buf[i];
        // CSV: added bucket_id after window_id
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s->device_id, s->window_id, s->bucket_id,
               s->workload, s->attack_type, s->attack_level, s->compromised, s->leaf_label,
               s->dC, s->dL, s->dP, s->dE, s->dF, s->dS, s->dT,
               s->cyc_per_us, s->lsu_per_cyc, s->cpi_per_cyc, s->exc_per_cyc, s->fold_per_cyc);
    }
}

static void collect_exact_samples(uint32_t target_n) {
    uint32_t collected = 0;

    while (collected < target_n) {
        run_workload_step(current_workload);

        sample_t s;
        while (collected < target_n && ring_pop(&s)) {
            bucket_buf[collected++] = s;
        }
    }
}

static void run_bucket(uint32_t workload, attack_t atk, uint32_t level, uint32_t n) {
    // assign a new bucket id (important for group split)
    current_bucket_id = bucket_id_g++;

    // labels for this bucket
    current_workload     = workload;
    current_attack_type  = atk;
    current_attack_level = level;

    // collect without printing
    collect_exact_samples(n);

    // stop, dump, reset, restart
    stop_timers();
    dump_bucket(bucket_buf, n);

    reset_sampling_state();
    start_timers();
}

// ===================== main =====================
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();

    srand((unsigned)time_us_64());

    for (uint32_t i = 0; i < RW_BUF_N; i++) rw_buf[i] = (0xA5A5A5A5u ^ i);

    dwt_enable_all();
    reset_sampling_state();

    // CSV header
    printf("device_id,window_id,bucket_id,workload,attack_type,attack_level,compromised,leaf_label,"
           "dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    start_timers();

    // --------------------------
    // SAFE buckets (more + varied)
    // leaf_label = 0/1/2
    // --------------------------
    for (int r = 0; r < SAFE_REPEATS; r++) {
        run_bucket(0, ATTACK_NONE, 0, SAMPLES_PER_BUCKET);
        run_bucket(1, ATTACK_NONE, 0, SAMPLES_PER_BUCKET);
        run_bucket(2, ATTACK_NONE, 0, SAMPLES_PER_BUCKET);
    }

    // --------------------------
    // ROP buckets: vary workload and level
    // leaf_label = 3
    // --------------------------
    run_bucket(0, ATTACK_ROP, 1, SAMPLES_PER_BUCKET);
    run_bucket(1, ATTACK_ROP, 1, SAMPLES_PER_BUCKET);
    run_bucket(2, ATTACK_ROP, 1, SAMPLES_PER_BUCKET);

    run_bucket(0, ATTACK_ROP, 2, SAMPLES_PER_BUCKET);
    run_bucket(1, ATTACK_ROP, 2, SAMPLES_PER_BUCKET);
    run_bucket(2, ATTACK_ROP, 2, SAMPLES_PER_BUCKET);

    // --------------------------
    // INJ buckets
    // leaf_label = 4
    // --------------------------
    run_bucket(0, ATTACK_INJ, 1, SAMPLES_PER_BUCKET);
    run_bucket(1, ATTACK_INJ, 1, SAMPLES_PER_BUCKET);
    run_bucket(2, ATTACK_INJ, 1, SAMPLES_PER_BUCKET);

    run_bucket(0, ATTACK_INJ, 2, SAMPLES_PER_BUCKET);
    run_bucket(1, ATTACK_INJ, 2, SAMPLES_PER_BUCKET);
    run_bucket(2, ATTACK_INJ, 2, SAMPLES_PER_BUCKET);

    stop_timers();

    // diagnostics as comment lines (CSV-safe if you ignore lines starting with '#')
    printf("# DONE\n");
    printf("# dropped_ring_pushes=%u\n", (unsigned)dropped_ring_pushes);
    printf("# total_buckets=%u\n", (unsigned)bucket_id_g);

    while (1) sleep_ms(1000);
}
