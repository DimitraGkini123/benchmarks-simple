#include "pico/stdlib.h"
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

// ====================================================================
//   ARM Cortex-M33 DWT performance counters
// ====================================================================
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

#define DEVICE_ID 4
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

// ====================================================================
//   BENCHMARK CONFIG
// ====================================================================
#define REPEATS 100
#define EEG_LEN 512
#define NUM_SIGNALS 30

static float eeg_raw[EEG_LEN];
static float eeg_filt[EEG_LEN];

// ====================================================================
//   LIGHT FIR FILTER 1–40 Hz
// ====================================================================
static const float bp_coef[21] = {
    -0.0042f,-0.0061f,-0.0079f,-0.0091f,-0.0093f,
    -0.0078f,-0.0042f, 0.0021f, 0.0110f, 0.0218f,
     0.0332f, 0.0440f, 0.0530f, 0.0592f, 0.0620f,
     0.0612f, 0.0568f, 0.0494f, 0.0399f, 0.0291f,
     0.0177f
};

static void fir(const float *in, float *out, int N, const float *h, int M)
{
    for (int n = 0; n < N; n++) {
        float acc = 0.0f;
        for (int k = 0; k < M; k++) {
            if (n - k >= 0)
                acc += h[k] * in[n-k];
        }
        out[n] = acc;
    }
}

//   SEIZURE FEATURES


// Variance (Activity)
static float feat_variance(const float *x, int N)
{
    float mean = 0;
    for (int i=0;i<N;i++) mean += x[i];
    mean /= (float)N;

    float v=0;
    for (int i=0;i<N;i++){
        float d = x[i]-mean;
        v += d*d;
    }
    return v / (float)N;
}

// Line Length / Coastline
static float feat_coastline(const float *x, int N)
{
    float c = 0.0f;
    for (int i = 1; i < N; i++)
        c += fabsf(x[i] - x[i-1]);
    return c;
}

// Nonlinear Energy (Teager-Kaiser)
static float feat_nle(const float *x, int N)
{
    float e = 0.0f;
    for (int n=1;n<N-1;n++)
        e += (x[n]*x[n] - x[n-1]*x[n+1]);
    return e / (float)(N-2);
}

// Basic rule-based classifier: 2-of-3 thresholding
static int detect_seizure(float var, float coast, float nle)
{
    int score = 0;
    if (var   > 0.010f) score++;
    if (coast > 19.0f)  score++;
    if (nle   > 0.017f) score++;
    return (score >= 2);
}
// ---------- synthetic signals (workload “difficulty”) ----------
static void generate_light(float fs) {
    for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;
        float alpha = 0.5f * sinf(2.0f*(float)M_PI*10.0f*t);
        float theta = 0.2f * sinf(2.0f*(float)M_PI*6.0f*t);
        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.015f;
        eeg_raw[i] = alpha + theta + noise;
    }
}

static void generate_medium(float fs) {
    for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;
        float alpha = 0.6f * sinf(2.0f*(float)M_PI*10.0f*t);
        float beta  = 0.45f* sinf(2.0f*(float)M_PI*18.0f*t);
        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.035f;
        eeg_raw[i] = alpha + beta + noise;
    }
}

static void generate_heavy(float fs) {
    for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;
        float bg = 0.4f*sinf(2.0f*(float)M_PI*9.0f*t) + 0.3f*sinf(2.0f*(float)M_PI*5.0f*t);
        float burst = (i > 200 && i < 350) ? 1.2f*sinf(2.0f*(float)M_PI*22.0f*t) : 0.0f;
        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.05f;
        eeg_raw[i] = bg + burst + noise;
    }
}

// sink so compiler can’t optimize away
static volatile float sink_f = 0.0f;
static volatile int sink_i = 0;

static inline void run_workload_step(int label) {
    const float fs = 250.0f;

    // 1) generate signal (each step has randomness)
    if (label == 0) generate_light(fs);
    else if (label == 1) generate_medium(fs);
    else generate_heavy(fs);

    // 2) FIR once (baseline)
    fir(eeg_raw, eeg_filt, EEG_LEN, bp_coef, 21);

    // 3) features once
    float v = feat_variance(eeg_filt, EEG_LEN);
    float c = feat_coastline(eeg_filt, EEG_LEN);
    float n = feat_nle(eeg_filt, EEG_LEN);
    int seiz = detect_seizure(v, c, n);

    sink_f += (v + c + n);
    sink_i ^= seiz;

    // ---------------- MEDIUM: a bit heavier ----------------
    if (label == 1) {
        // extra FIR pass (costly + deterministic)
        fir(eeg_filt, eeg_filt, EEG_LEN, bp_coef, 21);

        // one extra feature pass
        v = feat_variance(eeg_filt, EEG_LEN);
        c = feat_coastline(eeg_filt, EEG_LEN);
        n = feat_nle(eeg_filt, EEG_LEN);
        seiz = detect_seizure(v, c, n);

        sink_f += (0.5f*v + 0.5f*c + 0.5f*n);
        sink_i ^= (seiz << 1);
    }

    // ---------------- HEAVY: ALWAYS heavier than MEDIUM ----------------
    if (label == 2) {
        // 2 extra FIR passes (total = 3 FIRs including baseline)
        fir(eeg_filt, eeg_filt, EEG_LEN, bp_coef, 21);
        fir(eeg_filt, eeg_filt, EEG_LEN, bp_coef, 21);

        // 4 extra feature passes (total features passes > medium)
        for (int rep = 0; rep < 4; rep++) {
            v = feat_variance(eeg_filt, EEG_LEN);
            c = feat_coastline(eeg_filt, EEG_LEN);
            n = feat_nle(eeg_filt, EEG_LEN);
            seiz = detect_seizure(v, c, n);

            sink_f += (v + 0.1f*c + 0.01f*n);
            sink_i ^= (seiz + rep);
        }

    }

    // make LIGHT a bit more idle (optional)
    if (label == 0) sleep_ms(1);
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
    uint32_t label;

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

    dwt_enable_all();

    prev_t_us = time_us_64();
    prev_cyc  = DWT_CYCCNT;
    prev_lsu8   = (uint8_t)DWT_LSUCNT;
    prev_cpi8   = (uint8_t)DWT_CPICNT;
    prev_exc8   = (uint8_t)DWT_EXCCNT;
    prev_fold8  = (uint8_t)DWT_FOLDCNT;
    prev_sleep8 = (uint8_t)DWT_SLEEPCNT;

    printf("device_id,window_id,label,dC,dL,dP,dE,dF,dS,dT,cyc_per_us,lsu_per_cyc,cpi_per_cyc,exc_per_cyc,fold_per_cyc\n");

    struct repeating_timer t2ms, t100ms;
    add_repeating_timer_ms(-2,   timer_2ms_cb,   NULL, &t2ms);
    add_repeating_timer_ms(-100, timer_100ms_cb, NULL, &t100ms);

    const uint32_t windows_per_class = 300;

    for (int phase = 0; phase < 3; phase++) {
        current_label = (uint32_t)phase;
        uint32_t end_window = window_id + windows_per_class;

        while (window_id < end_window) {
            run_workload_step((int)current_label);

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