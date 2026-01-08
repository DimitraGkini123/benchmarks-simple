#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "pico/stdlib.h"

// Δηλώνονται από το linker script του Pico SDK
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

    DWT_CYCCNT = 0;
    DWT_CPICNT = 0;
    DWT_EXCCNT = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT = 0;
    DWT_FOLDCNT = 0;

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

// =================== Workload Components ====================
#define LEN 512
static double sig_in[LEN];
static double sig_filt[LEN];

// -----------------------------------------------------------
// FIR Low-Pass Filter Coefficients (M=8)
// fs = 250 Hz, fc ≈ 4 Hz (Ενδεικτικοί Συντελεστές)
// -----------------------------------------------------------
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
// -----------------------------------------------------------
// Generate synthetic ECG-like signal (ECG + tremor + noise)
// -----------------------------------------------------------
static void generate_light_signal(double fs)
{
    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double f_ecg = 1.0 + ((rand()%40)/100.0);  
        double ecg = 0.7 * sin(2*M_PI*f_ecg * t);
        double tremor_amp = 0.05 + ((rand()%50)/1000.0); // 0.05–0.1
        double tremor = tremor_amp * sin(2*M_PI*4.0 * t);
        double noise  = ((rand()%2000)/1000.0 - 1.0) * 0.02;
        sig_in[i] = ecg + tremor + noise;
    }
}
static void generate_medium_signal(double fs)
{
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);     // 1.0 – 1.4 Hz
    double f_tremor = 5.5 + ((rand() % 100) / 100.0); // 5.5 – 6.5 Hz
    double tremor_amp = 0.25 + ((rand() % 100) / 1000.0); // 0.25 – 0.35
    double noise_amp = 0.03 + ((rand() % 20) / 1000.0);   // 0.03 – 0.05

    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * f_ecg * t);
        double tremor = tremor_amp * sin(2 * M_PI * f_tremor * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * noise_amp;
        sig_in[i] = ecg + tremor + noise;
    }
}

static void generate_heavy_signal(double fs)
{
    double f_ecg = 1.0 + ((rand() % 40) / 100.0);      // 1.0 – 1.4 Hz
    double f_tremor = 7.5 + ((rand() % 150) / 100.0); // 7.5 – 9.0 Hz
    double tremor_amp = 0.5 + ((rand() % 200) / 1000.0); // 0.5 – 0.7
    double noise_amp = 0.06 + ((rand() % 30) / 1000.0);  // 0.06 – 0.09

    for (size_t i = 0; i < LEN; i++) {
        double t = i / fs;
        double ecg    = 0.7 * sin(2 * M_PI * f_ecg * t);
        double tremor = tremor_amp * sin(2 * M_PI * f_tremor * t);
        double noise  = ((rand() % 2000) / 1000.0 - 1.0) * noise_amp;
        sig_in[i] = ecg + tremor + noise;
    }
}


// -----------------------------------------------------------
// Low Pass filter (M-point)
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

            size_t skip = (size_t)(fs * 0.4);  // refractory period ~400ms
            i += skip;
            if (i + 1 >= len) break;
        }
    }

    double dur = (double)len / fs;
    return dur > 0 ? (peaks / dur) * 60.0 : 0.0;
}

// -----------------------------------------------------------
//  Healthcare HR workload--> this is where the worload is being excuted
// 1000 times and it is being benchmarked by taking the mean and std of every metric
// -----------------------------------------------------------

typedef struct {
    double mean;
    double M2;      // sum of squared deviations
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
#define REPEATS 100

void benchmark_one_signal(
        void (*signal_fn)(double),
        int signal_id,
        int class_label)
{
    double fs = 250.0;

    signal_fn(fs);  // generate new signal

    Stats stC, stL, stP, stF, stT;
    stats_init(&stC);
    stats_init(&stL);
    stats_init(&stP);
    stats_init(&stF);
    stats_init(&stT);

    for(int r=0;r<REPEATS;r++){

        dwt_enable_all();
        uint64_t t0=time_us_64();

        //βασικό pipeline που τρέχει για όλα τα modes. 
        low_pass_fir(sig_in,sig_filt,LEN,lp_coefficients,LPF_ORDER);
        compute_hr(sig_filt,LEN,fs,0.2);
        //αν έχουμε medium worload --> 2ο πέρασμα φίλτρου
        if (class_label == 1) {
              low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
        }
        else if (class_label == 2) {
            //αν έχουμε heavy 
            for (int k = 0; k < 3; ++k) {
                low_pass_fir(sig_filt, sig_filt, LEN, lp_coefficients, LPF_ORDER);
            }
             double sum_diff = 0.0;
            for (size_t i = 1; i < LEN; ++i) {
                double d = sig_filt[i] - sig_filt[i - 1];
                sum_diff += (d >= 0) ? d : -d;
            }
            // απλά για να μη γίνει optimize-out
            __asm volatile ("" :: "r"(sum_diff) : "memory");
        }
        uint64_t t1=time_us_64();

        stats_push(&stC, (double)DWT_CYCCNT);
        stats_push(&stL, (double)DWT_LSUCNT);
        stats_push(&stP, (double)DWT_CPICNT);
        stats_push(&stF, (double)DWT_FOLDCNT);
        stats_push(&stT, (double)(t1 - t0));
    }

    // CSV LINE
 printf("%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d\n",
           DEVICE_ID,
           signal_id,
           stC.mean, stats_std(&stC),
           stL.mean, stats_std(&stL),
           stP.mean, stats_std(&stP),
           stF.mean, stats_std(&stF),
           stT.mean, stats_std(&stT),
           class_label
    );
}

// ===========================================================
// ============================== MAIN ========================
// ===========================================================

int main(void)
{
    stdio_init_all();
    wait_for_usb_connection();
    uint32_t fw_hash = firmware_hash_fnv1a();

    printf("device id, signal,meanC,stdC,meanL,stdL,meanP,stdP,meanF,stdF,meanT,stdT,label\n");

    int NUM = 300;
    srand(time_us_64());   // για randomness
    printf("# FW_HASH_FNV1A=0x%08lx\n", (unsigned long)fw_hash);

    printf("\n===== LIGHT WORKLOADS =====\n\n");
    for(int i=0;i<NUM;i++) benchmark_one_signal(generate_light_signal, i, 0);
    printf("\n===== MEDIUM WORKLOADS =====\n\n");
    for(int i=0;i<NUM;i++) benchmark_one_signal(generate_medium_signal, i, 1);
    printf("\n===== HEAVY WORKLOADS =====\n\n");
    for(int i=0;i<NUM;i++) benchmark_one_signal(generate_heavy_signal, i, 2);


    printf("DONE.\n");

    while (1) sleep_ms(1000);
}
