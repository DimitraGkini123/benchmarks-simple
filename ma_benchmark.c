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
#define REPEATS 1000  //επαναλήψεις για benchmark 
static double sig_in[LEN];
static double sig_filt[LEN];

// -----------------------------------------------------------
// Generate synthetic ECG-like signal (ECG + tremor + noise)
// -----------------------------------------------------------
static void generate_ecg_signal(double fs)
{
    for (size_t i = 0; i < LEN; i++) {
        double t = (double)i / fs;

        double ecg    = 0.7 * sin(2*M_PI*1.2 * t);   // ~72 bpm
        double tremor = 0.2 * sin(2*M_PI*6.0 * t);   // 6 Hz
        double noise  = ((rand()%2000)/1000.0 - 1.0) * 0.03;

        sig_in[i] = ecg + tremor + noise;
    }
}

// -----------------------------------------------------------
// Moving average filter (M-point)
// -----------------------------------------------------------
static void moving_average_filter(const double *in, double *out, size_t len, int M)
{
    for (size_t n = 0; n < len; n++) {
        double sum = 0.0; 
        int c = 0;
        for (int k = 0; k < M; k++) {
            if (n >= (size_t)k) { 
                sum += in[n - k]; 
                c++; 
            }
        }
        out[n] = c ? (sum / c) : 0.0;
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
//  Healthcare HR workload (this is benchmarked)
//this is where the worload is being excuted
// 1000 times and it is being benchmarked 
//by taking the mean and std of every metric
// -----------------------------------------------------------
void workload_healthcare_hr(void)
{
    double fs=250.0; // typical ECG/PPG sampling rate
 
    // 1. ΔΗΜΙΟΥΡΓΙΑ ΣΗΜΑΤΟΣ (ΕΚΤΟΣ ΒΡΟΧΟΥ ΕΠΑΝΑΛΗΨΗΣ)  
     generate_ecg_signal(fs);
    
    // 2. ΜΕΤΑΒΛΗΤΕΣ ΓΙΑ ΣΤΑΤΙΣΤΙΚΑ (Accumulators)
    double sum_cycles = 0.0, sum_sq_cycles = 0.0;
    double sum_lsu = 0.0, sum_sq_lsu = 0.0;
    double sum_cpi = 0.0, sum_sq_cpi = 0.0;
    double sum_folded = 0.0, sum_sq_folded = 0.0;

    uint64_t time_measurements[REPEATS];

    // Πρέπει να δηλωθεί ως volatile για να μην αφαιρεθεί από τον compiler
    volatile double total_hr = 0.0; 

    // 3. ΒΡΟΧΟΣ ΕΠΑΝΑΛΗΨΗΣ (MEASUREMENT LOOP)
    for (int r = 0; r < REPEATS; r++) {
        uint64_t start_time, end_time;
        uint32_t cycles, lsu, cpi, folded;

        // --- START MEASUREMENT ---
        dwt_enable_all(); // Επαναρχικοποίηση μετρητών
        start_time = time_us_64();
        // --- EXECUTE WORKLOAD ---
         moving_average_filter(sig_in, sig_filt, LEN, 8);
         double hr = compute_hr(sig_filt, LEN, fs, 0.2);
     
        // --- STOP/READ MEASUREMENT ---
        end_time = time_us_64();
        cycles = DWT_CYCCNT;
        lsu = DWT_LSUCNT;
        cpi = DWT_CPICNT;
        folded = DWT_FOLDCNT;
        time_measurements[r] = end_time - start_time;
        // Χρήση του HR για να μην αφαιρεθεί η κλήση από τον compiler
        total_hr += hr; 

        // 4. ΣΥΓΚΕΝΤΡΩΣΗ ΔΕΔΟΜΕΝΩΝ ΓΙΑ ΣΤΑΤΙΣΤΙΚΑ
        double d_cycles = (double)cycles;
        double d_lsu = (double)lsu;
        double d_cpi = (double)cpi;
        double d_folded = (double)folded;

        //Cycles
        sum_cycles += d_cycles;
        sum_sq_cycles += (d_cycles * d_cycles);
        // LSU Stalls
        sum_lsu += d_lsu;
        sum_sq_lsu += (d_lsu * d_lsu);
        
        // CPI Stalls
        sum_cpi += d_cpi;
        sum_sq_cpi += (d_cpi * d_cpi);

        // Folded Instructions
        sum_folded += d_folded;
        sum_sq_folded += (d_folded * d_folded);
    }
    // ΥΠΟΛΟΓΙΣΜΟΣ ΣΤΑΤΙΣΤΙΚΩΝ ΧΡΟΝΟΥ (Time)
double sum_time = 0.0, sum_sq_time = 0.0;
    for (int r = 0; r < REPEATS; r++) {
        double d_time = (double)time_measurements[r];
        sum_time += d_time;
        sum_sq_time += (d_time * d_time);
    }

    //  ΤΕΛΙΚΟΣ ΥΠΟΛΟΓΙΣΜΟΣ ΧΑΡΑΚΤΗΡΙΣΤΙΚΩΝ (FEATURES)
    
    // Συνάρτηση για υπολογισμό Τυπικής Απόκλισης
    #define CALCULATE_STATS(SUM, SUM_SQ, MEAN_VAR, STDDEV_VAR) \
        MEAN_VAR = SUM / REPEATS; \
        double variance_##STDDEV_VAR = (SUM_SQ / REPEATS) - (MEAN_VAR * MEAN_VAR); \
        STDDEV_VAR = (variance_##STDDEV_VAR > 0) ? sqrt(variance_##STDDEV_VAR) : 0.0;

    double mean_cycles, std_dev_cycles;
    double mean_lsu, std_dev_lsu;
    double mean_cpi, std_dev_cpi;
    double mean_folded, std_dev_folded;
    double mean_time, std_dev_time;
    
    CALCULATE_STATS(sum_cycles, sum_sq_cycles, mean_cycles, std_dev_cycles);
    CALCULATE_STATS(sum_lsu, sum_sq_lsu, mean_lsu, std_dev_lsu);
    CALCULATE_STATS(sum_cpi, sum_sq_cpi, mean_cpi, std_dev_cpi);
    CALCULATE_STATS(sum_folded, sum_sq_folded, mean_folded, std_dev_folded);
    CALCULATE_STATS(sum_time, sum_sq_time, mean_time, std_dev_time);

    #undef CALCULATE_STATS

    
    // 7. ΕΚΤΥΠΩΣΗ ΤΩΝ ΧΑΡΑΚΤΗΡΙΣΤΙΚΩΝ (FEATURES)
    printf("--- ML Attestation Features (N=%d) ---\n", REPEATS);
    printf("Mean HR (Debug): %.2f bpm\n", total_hr / REPEATS);

    printf("\n[1] CYCLES:\n");
    printf("  Mean (μ): %.2f\n", mean_cycles);
    printf("  Std Dev (σ): %.2f\n", std_dev_cycles);
    
    printf("\n[2] LSU STALLS:\n");
    printf("  Mean (μ): %.2f\n", mean_lsu);
    printf("  Std Dev (σ): %.2f\n", std_dev_lsu);
    
    printf("\n[3] CPI STALLS:\n");
    printf("  Mean (μ): %.2f\n", mean_cpi);
    printf("  Std Dev (σ): %.2f\n", std_dev_cpi);

    printf("\n[4] FOLDED INSTR:\n");
    printf("  Mean (μ): %.2f\n", mean_folded);
    printf("  Std Dev (σ): %.2f\n", std_dev_folded);

    printf("\n[5] TIME (us) (μ-Time):\n");
    printf("  Mean (μ): %.2f\n", mean_time);
    printf("  Std Dev (σ): %.2f\n", std_dev_time);
    
    printf("---------------------------------------\n");

}

// ===========================================================
// =================== Benchmark Wrapper ======================
// ===========================================================
static void run_benchmark(const char *label, void (*fn)(void), int repeats)
{
printf("\n=== Running: %s (x%d repeats) ===\n", label, repeats);

uint64_t start_us = time_us_64();

fn(); // Εκτελεί το workload με τις επαναλήψεις

uint64_t end_us = time_us_64();

    // Εδώ τυπώνουμε μόνο το συνολικό χρόνο για τις 1000 επαναλήψεις.
    // Οι λεπτομέρειες των DWT τυπώνονται μέσα στη workload.
printf("\nTime (us):  %llu (Total Time for %d runs)\n", end_us - start_us, repeats);
printf("==========================\n");
}

// ===========================================================
// ============================ MAIN ==========================
// ===========================================================
int main(void)
{
    stdio_init_all();
    wait_for_usb_connection();

    printf("\nPico 2 W — Healthcare HR Benchmark\n");

  run_benchmark("HR Analysis (Attestation Features)", workload_healthcare_hr, REPEATS);

    printf("\nAll benchmarks complete.\n");

    while (true) {
        sleep_ms(1000);
    }
}
