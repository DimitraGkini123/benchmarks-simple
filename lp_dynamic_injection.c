// ===========================================================
//  Pico Firmware Benchmark: 900 SAFE + 900 COMPROMISED windows (CSV)
//  - SAFE: runs healthcare-like pipeline only
//  - COMPROMISED: runs same pipeline + malicious_micro_payload()
//  - Balanced across workloads so "compromised" != "heavy"
//
//  CSV columns:
//   device_id,window_id,meanC,stdC,meanL,stdL,meanP,stdP,meanF,stdF,meanT,stdT,workload_label,compromised
//
//  workload_label: 0=LIGHT, 1=MEDIUM, 2=HEAVY
//  compromised:    0=SAFE, 1=COMPROMISED
// ===========================================================

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "pico/stdlib.h"

// Declared by the Pico SDK linker script
extern const uint8_t __flash_binary_start;
extern const uint8_t __flash_binary_end;

static uint32_t firmware_hash_fnv1a(void) {
    const uint8_t *p   = &__flash_binary_start;
    const uint8_t *end = &__flash_binary_end;

    uint32_t hash = 0x811C9DC5u;      // FNV offset basis
    while (p < end) {
        hash ^= *p++;
        hash *= 0x01000193u;          // FNV prime
    }
    return hash;
}

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

// -----------------------------------------------------------
// Wait for USB serial
// -----------------------------------------------------------
static void wait_for_usb_connection(void) {
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

// FIR Low-Pass Filter Coefficients (M=8), fs=250 Hz, fc~4 Hz (indicative)
#define LPF_ORDER 8
static const double lp_coefficients[LPF_ORDER] = {
    -0.00511,
     0.01017,
     0.05730,
     0.20164,
     0.47291,
     0.20164,
     0.05730,
     0.01017
};

static void generate_light_signal(double fs) {
    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * 1.2 * t);
        double tremor = 0.1 * sin(2 * M_PI * 4.0 * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * 0.02;
        sig_in[i] = ecg + tremor + noise;
    }
}
static void generate_medium_signal(double fs) {
    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * 1.2 * t);
        double tremor = 0.3 * sin(2 * M_PI * 6.0 * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * 0.04;
        sig_in[i] = ecg + tremor + noise;
    }
}
static void generate_heavy_signal(double fs) {
    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * 1.2 * t);
        double tremor = 0.6 * sin(2 * M_PI * 8.0 * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * 0.07;
        sig_in[i] = ecg + tremor + noise;
    }
}

// -----------------------------------------------------------
// "Malicious" micro payload (simulated compromised behavior)
// -----------------------------------------------------------
__attribute__((noinline, section(".injected_dynamic"), used))
static void malicious_micro_payload(void) {
    static volatile uint8_t evil_buf[4096];

    // Chaotic memory access pattern
    for (int r = 0; r < 3; ++r) {
        for (int i = 0; i < 4096; ++i) {
            int idx = (i * 17 + r * 13) & 4095;
            evil_buf[idx] ^= (uint8_t)(i * 7 + r);
        }
    }

    // Branch-heavy arithmetic
    int acc = 0;
    for (int i = 0; i < 5000; ++i) {
        if ((i ^ (acc << 1)) & 1) acc += i;
        else                      acc ^= (i * 3);
    }

    __asm volatile("nop; nop; nop;");
}

// -----------------------------------------------------------
// Low-pass FIR
// -----------------------------------------------------------
static void low_pass_fir(const double *in, double *out, size_t len,
                         const double *h, int M)
{
    for (size_t n = 0; n < len; ++n) {
        double sum = 0.0;
        int kmax = (n < (size_t)(M - 1)) ? (int)n : (M - 1);
        for (int k = 0; k <= kmax; ++k) {
            sum += h[k] * in[n - (size_t)k];
        }
        out[n] = sum;
    }
}

// -----------------------------------------------------------
// Peak detection + HR estimation
// -----------------------------------------------------------
static double compute_hr(const double *x, size_t len, double fs, double thr)
{
    if (!x || len < 3 || fs <= 0.0) return 0.0;

    int peaks = 0;
    for (size_t i = 1; i + 1 < len; i++) {
        if (x[i] > x[i - 1] && x[i] > x[i + 1] && x[i] > thr) {
            peaks++;
            size_t skip = (size_t)(fs * 0.4);  // refractory ~400ms
            i += skip;
            if (i + 1 >= len) break;
        }
    }

    double dur = (double)len / fs;
    return dur > 0 ? (peaks / dur) * 60.0 : 0.0;
}

// ===========================================================
// ====================== Stats (Welford) =====================
// ===========================================================
typedef struct {
    double mean;
    double M2;
    long count;
} Stats;

static inline void stats_init(Stats *s) {
    s->mean = 0.0;
    s->M2 = 0.0;
    s->count = 0;
}
static inline void stats_push(Stats *s, double x) {
    s->count++;
    double delta = x - s->mean;
    s->mean += delta / s->count;
    double delta2 = x - s->mean;
    s->M2 += delta * delta2;
}
static inline double stats_variance(const Stats *s) {
    return (s->count > 1) ? (s->M2 / (s->count - 1)) : 0.0;
}
static inline double stats_std(const Stats *s) {
    double v = stats_variance(s);
    return (v > 0.0) ? sqrt(v) : 0.0;
}

// ===========================================================
// ====================== Benchmark Window ====================
// ===========================================================

// How many repeats per window to compute mean/std
#define REPEATS 100

static void run_one_window(
        void (*signal_fn)(double),
        int window_id,
        int workload_label,   // 0/1/2
        bool compromised)     // 0 safe, 1 compromised
{
    const double fs = 250.0;

    // fresh signal per window
    signal_fn(fs);

    Stats stC, stL, stP, stF, stT;
    stats_init(&stC);
    stats_init(&stL);
    stats_init(&stP);
    stats_init(&stF);
    stats_init(&stT);

    for (int r = 0; r < REPEATS; r++) {
        dwt_enable_all();
        uint64_t t0 = time_us_64();

        // Base pipeline
        low_pass_fir(sig_in, sig_filt, LEN, lp_coefficients, LPF_ORDER);
        compute_hr(sig_filt, LEN, fs, 0.2);

        // Workload scaling
        if (workload_label == 1) {
            // medium: +1 extra pass
            low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
        } else if (workload_label == 2) {
            // heavy: +3 extra passes + extra compute
            for (int k = 0; k < 3; ++k) {
                low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
            }
            double sum_diff = 0.0;
            for (size_t i = 1; i < LEN; ++i) {
                double d = sig_filt[i] - sig_filt[i - 1];
                sum_diff += (d >= 0) ? d : -d;
            }
            __asm volatile ("" :: "r"(sum_diff) : "memory");
        }

        // Compromised behavior
        if (compromised) {
            malicious_micro_payload();
        }

        uint64_t t1 = time_us_64();

        stats_push(&stC, (double)DWT_CYCCNT);
        stats_push(&stL, (double)DWT_LSUCNT);
        stats_push(&stP, (double)DWT_CPICNT);
        stats_push(&stF, (double)DWT_FOLDCNT);
        stats_push(&stT, (double)(t1 - t0));
    }

    // CSV line
    printf("%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d\n",
           DEVICE_ID,
           window_id,
           stC.mean, stats_std(&stC),
           stL.mean, stats_std(&stL),
           stP.mean, stats_std(&stP),
           stF.mean, stats_std(&stF),
           stT.mean, stats_std(&stT),
           workload_label,
           compromised ? 1 : 0);
}

// ===========================================================
// ============================== MAIN ========================
// ===========================================================

#define NUM_SAFE_WINDOWS        900
#define NUM_COMP_WINDOWS        900
#define PER_WORKLOAD            300  // 900/3

int main(void)
{
    stdio_init_all();
    wait_for_usb_connection();

    srand((unsigned)time_us_64());

    uint32_t fw_hash = firmware_hash_fnv1a();
    printf("# FW_HASH_FNV1A=0x%08lx\n", (unsigned long)fw_hash);
    printf("# FIRMWARE VARIANT: 900_SAFE_900_COMPROMISED_BALANCED\n");

    // CSV header
    printf("device_id,window_id,meanC,stdC,meanL,stdL,meanP,stdP,meanF,stdF,meanT,stdT,workload_label,compromised\n");

    int window_id = 0;

    // -------------------------
    // SAFE (900), balanced: 300 L + 300 M + 300 H
    // -------------------------
    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_light_signal,  window_id++, 0, false);

    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_medium_signal, window_id++, 1, false);

    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_heavy_signal,  window_id++, 2, false);

    // -------------------------
    // COMPROMISED (900), balanced: 300 L + 300 M + 300 H
    // -------------------------
    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_light_signal,  window_id++, 0, true);

    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_medium_signal, window_id++, 1, true);

    for (int i = 0; i < PER_WORKLOAD; i++)
        run_one_window(generate_heavy_signal,  window_id++, 2, true);

    // Sanity: window_id should be 1800
    printf("# DONE windows=%d (safe=%d, compromised=%d)\n", window_id, NUM_SAFE_WINDOWS, NUM_COMP_WINDOWS);

    while (1) sleep_ms(1000);
}
