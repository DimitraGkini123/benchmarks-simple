#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>

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

static inline void dwt_enable_all(void) {
    DEMCR |= DEMCR_TRCENA;
    DWT_LAR = 0xC5ACCE55;
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_EXCCNT = 0;
    DWT_SLEEPCNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA | DWT_CTRL_CPIEVTENA | DWT_CTRL_EXCEVTENA |
                DWT_CTRL_SLEEPEVTENA | DWT_CTRL_LSUEVTENA | DWT_CTRL_FOLDEVTENA;
}

static void wait_for_usb_connection(void) {
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(200);
}

// ===================== FFT pipeline =====================
#define FFT_N 256
#define FS_HZ 250.0
typedef struct { double r, i; } cpx_t;

static cpx_t fft_buf[FFT_N];
static double mag[FFT_N / 2];
static volatile double fft_sink = 0.0;

static inline cpx_t c_add(cpx_t a, cpx_t b) { return (cpx_t){a.r + b.r, a.i + b.i}; }
static inline cpx_t c_sub(cpx_t a, cpx_t b) { return (cpx_t){a.r - b.r, a.i - b.i}; }
static inline cpx_t c_mul(cpx_t a, cpx_t b) { return (cpx_t){a.r*b.r - a.i*b.i, a.r*b.i + a.i*b.r}; }

static void fft(cpx_t *buf, int n) {
    int i, j, k, m;
    for (i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j |= bit;
        if (i < j) { cpx_t tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp; }
    }
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
        }
    }
}

static void compute_mag(void) {
    for (int k = 0; k < FFT_N/2; k++) {
        mag[k] = sqrt(fft_buf[k].r * fft_buf[k].r + fft_buf[k].i * fft_buf[k].i);
    }
}

static double band_energy(double f0, double f1) {
    int k0 = (int)(f0 * FFT_N / FS_HZ);
    int k1 = (int)(f1 * FFT_N / FS_HZ);
    if (k0 < 0) k0 = 0; if (k1 > FFT_N/2 - 1) k1 = FFT_N/2 - 1;
    double e = 0.0;
    for (int k = k0; k <= k1; k++) e += mag[k] * mag[k];
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
    }
}

// ===================== Aggregator Logic =====================
typedef struct {
    uint32_t sum_cyc, sum_lsu, sum_cpi, sum_exc, sum_fold, sum_sleep, sum_dt_us;
} agg_t;

static volatile agg_t agg = {0};
static uint32_t prev_cyc = 0;
static uint64_t prev_t_us = 0;
static uint8_t prev_lsu8 = 0, prev_cpi8 = 0, prev_exc8 = 0, prev_fold8 = 0, prev_sleep8 = 0;

typedef struct {
    uint32_t device_id, window_id, label, dC, dL, dP, dE, dF, dS, dT;
    float cyc_per_us, lsu_per_cyc, cpi_per_cyc, exc_per_cyc, fold_per_cyc;
} sample_t;

#define RING_N 256
static volatile sample_t ring[RING_N];
static volatile uint32_t w_idx = 0, r_idx = 0;

static inline bool ring_push(const sample_t *s) {
    uint32_t next = (w_idx + 1u) % RING_N;
    if (next == r_idx) return false;
    ring[w_idx] = *s; w_idx = next; return true;
}

static inline bool ring_pop(sample_t *out) {
    if (r_idx == w_idx) return false;
    *out = ring[r_idx]; r_idx = (r_idx + 1u) % RING_N; return true;
}

static volatile uint32_t current_label = 0;
static volatile uint32_t window_id = 0;

// Callbacks
bool timer_2ms_cb(struct repeating_timer *t) {
    uint64_t now = time_us_64();
    uint32_t dt = (uint32_t)(now - prev_t_us); prev_t_us = now;
    uint32_t cyc = DWT_CYCCNT;
    uint32_t dC = cyc - prev_cyc; prev_cyc = cyc;

    uint8_t lsu8 = (uint8_t)DWT_LSUCNT, cpi8 = (uint8_t)DWT_CPICNT, exc8 = (uint8_t)DWT_EXCCNT, 
            fold8 = (uint8_t)DWT_FOLDCNT, sleep8 = (uint8_t)DWT_SLEEPCNT;

    agg.sum_dt_us += dt; agg.sum_cyc += dC;
    agg.sum_lsu += (uint8_t)(lsu8 - prev_lsu8);
    agg.sum_cpi += (uint8_t)(cpi8 - prev_cpi8);
    agg.sum_exc += (uint8_t)(exc8 - prev_exc8);
    agg.sum_fold += (uint8_t)(fold8 - prev_fold8);
    agg.sum_sleep += (uint8_t)(sleep8 - prev_sleep8);

    prev_lsu8=lsu8; prev_cpi8=cpi8; prev_exc8=exc8; prev_fold8=fold8; prev_sleep8=sleep8;
    return true;
}

bool timer_100ms_cb(struct repeating_timer *t) {
    agg_t a = agg; agg = (agg_t){0};
    float active_cycles = (float)(a.sum_cyc - a.sum_sleep);
    if (active_cycles <= 0) active_cycles = 1.0f;
    float fdT = (a.sum_dt_us > 0) ? (float)a.sum_dt_us : 1.0f;
    float fdC = (a.sum_cyc > 0) ? (float)a.sum_cyc : 1.0f;

    sample_t s = { .device_id = DEVICE_ID, .window_id = window_id++, .label = current_label,
                   .dT = a.sum_dt_us, .dC = a.sum_cyc, .dL = a.sum_lsu, .dP = a.sum_cpi,
                   .dE = a.sum_exc, .dF = a.sum_fold, .dS = a.sum_sleep,
                   .cyc_per_us = (float)a.sum_cyc / fdT, .lsu_per_cyc = (float)a.sum_lsu / fdC,
                   .cpi_per_cyc = (float)a.sum_cpi / fdC, .exc_per_cyc = (float)a.sum_exc / fdC,
                   .fold_per_cyc = (float)a.sum_fold / fdC };
  
    ring_push(&s);
    return true;
}

// ===================== Workload Router =====================
static inline void run_workload_step(int label) {
    if (label == 0) { // LIGHT
        generate_fft_signal(4.0, 0.05);
        fft(fft_buf, FFT_N);
        compute_mag();
        fft_sink += band_energy(3.0, 10.0) / (band_energy(0.5, 3.0) + 1e-6);
        
    } 
    else if (label == 1) { // MEDIUM
        generate_fft_signal(6.0, 0.25);
        fft(fft_buf, FFT_N); fft(fft_buf, FFT_N);
        compute_mag();
        fft_sink += (band_energy(3.0, 10.0) + band_energy(10.0, 40.0)) / (band_energy(0.5, 3.0) + 1e-6);
    } 
    else { // HEAVY
        generate_fft_signal(8.5, 0.50);
        for (int i = 0; i < 4; i++) fft(fft_buf, FFT_N);
        compute_mag();
        double e1 = band_energy(0.5, 3.0), e2 = band_energy(3.0, 10.0), e3 = band_energy(10.0, 40.0);
        volatile double acc = 0.0;
        for (int i = 0; i < 500; i++) { acc += e3 / (e2 + 1e-6); acc *= 0.995; }
        fft_sink += acc;
    }

    __asm volatile ("wfi");
}

int main(void) {
    stdio_init_all(); wait_for_usb_connection(); dwt_enable_all();
    prev_t_us = time_us_64(); prev_cyc = DWT_CYCCNT;
    prev_lsu8 = (uint8_t)DWT_LSUCNT; prev_cpi8 = (uint8_t)DWT_CPICNT;

    printf("device_id,window_id,label,dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc,\n");

    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2, timer_2ms_cb, NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    for (int phase = 0; phase < 3; phase++) {
        current_label = (uint32_t)phase;
        uint32_t end_window = window_id + 300;
        while (window_id < end_window) {
            run_workload_step((int)current_label);
            sample_t s;
            while (ring_pop(&s)) {
                printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                       s.device_id, s.window_id, s.label, s.dC, s.dL, s.dP, s.dE, s.dF, s.dS, s.dT,
                       s.cyc_per_us, s.lsu_per_cyc, s.cpi_per_cyc, s.exc_per_cyc, s.fold_per_cyc);
            }
        }
    }
    printf("DONE\n");
    while (1) sleep_ms(1000);
}