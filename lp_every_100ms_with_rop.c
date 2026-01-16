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

// ===================== Attack labels (SIMULATED anomaly, not a real exploit) =====================
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_ROP  = 1,
} attack_t;

static volatile attack_t  current_attack_type  = ATTACK_NONE;
static volatile uint32_t  current_attack_level = 0;   // 0/1/2
static inline uint32_t compromised_flag(void) { return (current_attack_type != ATTACK_NONE) ? 1u : 0u; }

// Map to a single multiclass id (useful if you want one-label training)
// 0..2 = safe (light/medium/heavy)
// 3..8 = rop combos:
// 3 light_rop_L1, 4 light_rop_L2, 5 medium_rop_L1, 6 medium_rop_L2, 7 heavy_rop_L1, 8 heavy_rop_L2
static inline uint32_t class_id(uint32_t workload, uint32_t attack_type, uint32_t attack_level) {
    if (attack_type == ATTACK_NONE) return workload; // 0..2
    // rop:
    uint32_t lvl = (attack_level > 0) ? (attack_level - 1u) : 0u; // 0 or 1
    return 3u + workload * 2u + lvl;
}

// small buffer to create memory activity
#define RW_BUF_N 2048
static uint32_t rw_buf[RW_BUF_N];

// Simulated “ROP-like” anomaly: extra unexpected work + memory-walk
static inline void simulated_rop_payload(uint32_t level, double fs) {
    static double tmp[LEN];
    if (level == 0) return;

    // extra filtering pass on already-filtered data
    low_pass_fir(sig_filt, tmp, LEN, lp_coefficients, LPF_ORDER);

    // extra HR computations with different thresholds
    double hr1 = compute_hr(tmp, LEN, fs, 0.18);
    double hr2 = compute_hr(tmp, LEN, fs, 0.25);

    // memory walk (creates LSU/cache pressure)
    uint32_t acc = 0;
    uint32_t step = (level == 1) ? 17u : 7u;
    for (uint32_t i = 0; i < RW_BUF_N; i += step) {
        rw_buf[i] ^= (0x9E3779B9u + i);
        acc ^= rw_buf[i];
    }

    if (level >= 2) {
        // heavier: 2 more passes + more memory touch
        low_pass_fir(tmp, tmp, LEN, lp_coefficients, LPF_ORDER);
        (void)compute_hr(tmp, LEN, fs, 0.15);

        for (uint32_t i = 0; i < RW_BUF_N; i += 3u) {
            rw_buf[i] += (acc ^ i);
        }
    }

    __asm volatile("" :: "r"(hr1), "r"(hr2), "r"(acc) : "memory");
}

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

    // simulated "attack" work (if enabled)
    if (current_attack_type == ATTACK_ROP) {
        simulated_rop_payload(current_attack_level, fs);
    }

    // make LIGHT a bit more idle
    if (label == 0) sleep_ms(2);
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

    // labels (structured)
    uint32_t workload;       // 0/1/2
    uint32_t attack_type;    // 0=none, 1=rop
    uint32_t attack_level;   // 0/1/2
    uint32_t compromised;    // 0/1

    // optional single-class label
    uint32_t class_id;

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

// ===================== Global labels/window =====================
static volatile uint32_t current_workload = 0;
static volatile uint32_t window_id_g = 0;

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

    s.workload    = current_workload;
    s.attack_type = (uint32_t)current_attack_type;
    s.attack_level= current_attack_level;
    s.compromised = compromised_flag();
    s.class_id    = class_id(s.workload, s.attack_type, s.attack_level);

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

// ===================== main =====================
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();

    srand((unsigned)time_us_64());

    // init rw_buf
    for (uint32_t i = 0; i < RW_BUF_N; i++) rw_buf[i] = (0xA5A5A5A5u ^ i);

    dwt_enable_all();

    // init prevs
    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    // CSV header (now includes class_id)
    printf("device_id,window_id,workload,attack_type,attack_level,compromised,class_id,"
           "dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    // timers
    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    const uint32_t windows_per_bucket = 300;

    // ------------------------------------------
    // SAFE: (workload=0/1/2, attack=none)
    // ------------------------------------------
    for (uint32_t w = 0; w < 3; w++) {
        current_workload = w;
        current_attack_type  = ATTACK_NONE;
        current_attack_level = 0;

        uint32_t end_window = window_id_g + windows_per_bucket;
        while (window_id_g < end_window) {
            run_workload_step((int)current_workload);

            sample_t s;
            while (ring_pop(&s)) {
                printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                       s.device_id, s.window_id,
                       s.workload, s.attack_type, s.attack_level, s.compromised, s.class_id,
                       s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
                       s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
            }
        }
    }

    // ------------------------------------------
    // ROP: ALL workloads × BOTH intensity levels
    // (w=0/1/2) × (level=1/2)
    // ------------------------------------------
    for (uint32_t w = 0; w < 3; w++) {
        for (uint32_t lvl = 1; lvl <= 2; lvl++) {
            current_workload = w;
            current_attack_type  = ATTACK_ROP;
            current_attack_level = lvl;

            uint32_t end_window = window_id_g + windows_per_bucket;
            while (window_id_g < end_window) {
                run_workload_step((int)current_workload);

                sample_t s;
                while (ring_pop(&s)) {
                    printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                           s.device_id, s.window_id,
                           s.workload, s.attack_type, s.attack_level, s.compromised, s.class_id,
                           s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
                           s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
                }
            }
        }
    }

    // drain
    sample_t s;
    while (ring_pop(&s)) {
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s.device_id, s.window_id,
               s.workload, s.attack_type, s.attack_level, s.compromised, s.class_id,
               s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
               s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
    }

    cancel_repeating_timer(&t2ms);
    cancel_repeating_timer(&t100ms);

    printf("DONE\n");
    while (1) sleep_ms(1000);
}
