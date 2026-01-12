#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "pico/stdlib.h"

// ===========================================================
// ======================= DWT COUNTERS =======================
// ===========================================================
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

#define DEVICE_ID 3

static inline void dwt_enable_all(void) {
    DEMCR |= DEMCR_TRCENA;
    DWT_LAR = 0xC5ACCE55;  //unlock key 
    //zero-ing all the counters
    DWT_CYCCNT = 0;
    DWT_CPICNT = 0;
    DWT_EXCCNT = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT = 0;
    DWT_FOLDCNT = 0;
    //enable all the counters
    DWT_CTRL |= DWT_CTRL_CYCCNTENA |
                DWT_CTRL_CPIEVTENA |
                DWT_CTRL_EXCEVTENA |
                DWT_CTRL_SLEEPEVTENA |
                DWT_CTRL_LSUEVTENA |
                DWT_CTRL_FOLDEVTENA;
}

// -----------------------------------------------------------------------------
// VGA-style wait for USB
// -----------------------------------------------------------------------------
void wait_for_usb_connection() {
    while (!stdio_usb_connected()) {
        sleep_ms(100);
    }
    sleep_ms(200);
}

// ===========================================================
// =================== Workload Components ====================
// ===========================================================

#define LEN 512
static double sig_in[LEN];
static double sig_filt[LEN];

// ===================== Synthetic signals (ίδια λογική με πριν) =====================
#define LEN 512
static double sig_in[LEN];
static double sig_filt[LEN];

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

// ===================== Moving average filter =====================
// M-point causal MA: out[n] = (1/M) * sum_{k=0..M-1} in[n-k] (όπου υπάρχει)
static void moving_average_filter(const double *in, double *out, size_t len, int M) {
    for (size_t n = 0; n < len; n++) {
        double sum = 0.0;
        int c = 0;
        for (int k = 0; k < M; k++) {
            if (n >= (size_t)k) {
                sum += in[n - (size_t)k];
                c++;
            }
        }
        out[n] = c ? (sum / (double)c) : 0.0;
    }
}

// ===================== HR computation (όπως πριν) =====================
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

// ===================== Workload step (light/medium/heavy) =====================
// ΙΔΙΑ ΛΟΓΙΚΗ ΜΕ ΤΟ LPF:
// - LIGHT: 1 pass MA
// - MEDIUM: 2 passes MA
// - HEAVY: 4 passes MA
// + πάντα compute_hr μία φορά (ή και παραπάνω αν θες έξτρα load)
static inline void run_workload_step(int label) {
    const double fs = 250.0;

    // 1) Generate input by label
    if (label == 0) generate_light_signal(fs);
    else if (label == 1) generate_medium_signal(fs);
    else generate_heavy_signal(fs);

    // 2) Filtering intensity
    // επέλεξε M ανά label (προαιρετικό) — μεγαλύτερο M => περισσότερο compute
    int M = (label == 0) ? 8 : (label == 1) ? 16 : 32;

    // LIGHT: 1 pass
    moving_average_filter(sig_in, sig_filt, LEN, M);

    // MEDIUM: +1 pass (σύνολο 2)
    if (label == 1) {
        moving_average_filter(sig_filt, sig_filt, LEN, M);
    }
    // HEAVY: +3 passes (σύνολο 4)
    else if (label == 2) {
        for (int k = 0; k < 3; ++k) {
            moving_average_filter(sig_filt, sig_filt, LEN, M);
        }
    }

    // 3) HR estimation (κρατάς το ίδιο across labels για να μετράς κυρίως filtering load)
    hr_sink += compute_hr(sig_filt, LEN, fs, 0.2);
    if (label == 0) sleep_ms(2);

}
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

static inline bool ring_push(const sample_t *s) {
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) return false;
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

// ===================== main =====================
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();
    dwt_enable_all();

    // init prevs
    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;

    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    printf("device_id,window_id,label,dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    // timers
    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    const uint32_t windows_per_class = 300;

    for (int phase = 0; phase < 3; phase++) {
        current_label = (uint32_t)phase;
        uint32_t end_window = window_id + windows_per_class;

        while (window_id < end_window) {
            // keep CPU doing the workload; timers sample in background
            run_workload_step((int)current_label);

            // print ready samples from ring (SAFE in main)
            sample_t s;
            while (ring_pop(&s)) {
                printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                       s.device_id, s.window_id, s.label,
                       s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
                       s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
            }
        }
    }

    // drain
    sample_t s;
    while (ring_pop(&s)) {
        printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               s.device_id, s.window_id, s.label,
               s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
               s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
    }

    cancel_repeating_timer(&t2ms);
    cancel_repeating_timer(&t100ms);

    printf("DONE\n");
    while (1) sleep_ms(1000);
}
