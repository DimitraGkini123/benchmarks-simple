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

// ====================================================================
//   SEIZURE FEATURES
// ====================================================================

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

void generate_light(float fs)
{
    for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;

        float alpha = 0.5f * sinf(2*M_PI*10*t);  // 10 Hz
        float theta = 0.2f * sinf(2*M_PI*6*t);   // 6 Hz
        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.015f;

        eeg_raw[i] = alpha + theta + noise;
    }
}

void generate_medium(float fs)
{
   for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;

        float alpha = 0.6f * sinf(2*M_PI*10*t);
        float beta  = 0.45f * sinf(2*M_PI*18*t);   // pre-ictal β-rhythm
        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.035f;

        eeg_raw[i] = alpha + beta + noise;
    }
}
void generate_heavy(float fs)
{
for (int i = 0; i < EEG_LEN; i++) {
        float t = (float)i / fs;
        // background
        float bg = 0.4f * sinf(2*M_PI*9*t) +
                   0.3f * sinf(2*M_PI*5*t);
        // seizure burst between samples 200–350
        float burst = (i > 200 && i < 350)
                      ? 1.2f * sinf(2*M_PI*22*t)
                      : 0.0f;

        float noise = ((rand()%2000)/1000.0f - 1.0f) * 0.05f;
        eeg_raw[i] = bg + burst + noise;
    }
}

void benchmark_one(void (*gen)(float), int id, int label)
{
    float fs=250;

    double sumC=0, sqC=0;
    double sumL=0, sqL=0;
    double sumP=0, sqP=0;
    double sumF=0, sqF=0;
    double sumT=0, sqT=0;

    for(int r=0;r<REPEATS;r++){
        gen(fs);
        fir(eeg_raw, eeg_filt, EEG_LEN, bp_coef, 21);

        dwt_enable_all();
        uint64_t t0=time_us_64();

        float v=feat_variance(eeg_filt,EEG_LEN);
        float c=feat_coastline(eeg_filt,EEG_LEN);
        float n=feat_nle(eeg_filt,EEG_LEN);
        int seiz = detect_seizure(v,c,n);

        uint64_t t1=time_us_64();

        uint32_t C=DWT_CYCCNT;
        uint32_t L=DWT_LSUCNT;
        uint32_t P=DWT_CPICNT;
        uint32_t F=DWT_FOLDCNT;
        uint64_t T=t1-t0;

        sumC+=C; sqC+=C*C;
        sumL+=L; sqL+=L*L;
        sumP+=P; sqP+=P*P;
        sumF+=F; sqF+=F*F;
        sumT+=T; sqT+=T*T;
    }

    double meanC=sumC/REPEATS;
    double meanL=sumL/REPEATS;
    double meanP=sumP/REPEATS;
    double meanF=sumF/REPEATS;
    double meanT=sumT/REPEATS;

    double stdC=sqrt(sqC/REPEATS - meanC*meanC);
    double stdL=sqrt(sqL/REPEATS - meanL*meanL);
    double stdP=sqrt(sqP/REPEATS - meanP*meanP);
    double stdF=sqrt(sqF/REPEATS - meanF*meanF);
    double stdT=sqrt(sqT/REPEATS - meanT*meanT);

    printf("%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d\n",
        id,
        meanC,stdC,
        meanL,stdL,
        meanP,stdP,
        meanF,stdF,
        meanT,stdT,
        label);
}

// ====================================================================
// MAIN
// ====================================================================
int main(){
    stdio_init_all();
    wait_for_usb_connection();

    printf("id,meanC,stdC,meanL,stdL,meanP,stdP,meanF,stdF,meanT,stdT,label\n");

    for(int i=0;i<NUM_SIGNALS;i++) benchmark_one(generate_light,      i,            0);
    for(int i=0;i<NUM_SIGNALS;i++) benchmark_one(generate_medium,    100+i,        1);
    for(int i=0;i<NUM_SIGNALS;i++) benchmark_one(generate_heavy,       200+i,        2);

    printf("DONE.\n");
    while(1) sleep_ms(1000);
}