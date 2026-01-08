#include "pico/stdlib.h"
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

// ============================================================
//  ARM Cortex-M DWT registers
// ============================================================
#define DEMCR                (*(volatile uint32_t *)0xE000EDFC)
#define DEMCR_TRCENA         (1u << 24)

#define DWT_BASE             (0xE0001000u)
#define DWT_CTRL             (*(volatile uint32_t *)(DWT_BASE + 0x000))
#define DWT_CYCCNT           (*(volatile uint32_t *)(DWT_BASE + 0x004))
#define DWT_CPICNT           (*(volatile uint32_t *)(DWT_BASE + 0x008))
#define DWT_SLEEPCNT         (*(volatile uint32_t *)(DWT_BASE + 0x010))
#define DWT_LSUCNT           (*(volatile uint32_t *)(DWT_BASE + 0x014))
#define DWT_FOLDCNT          (*(volatile uint32_t *)(DWT_BASE + 0x018))
#define DWT_LAR              (*(volatile uint32_t *)(DWT_BASE + 0xFB0))

#define DWT_CTRL_CYCCNTENA   (1u << 0)
#define DWT_CTRL_CPIEVTENA   (1u << 17)
#define DWT_CTRL_SLEEPEVTENA (1u << 19)
#define DWT_CTRL_LSUEVTENA   (1u << 20)
#define DWT_CTRL_FOLDEVTENA  (1u << 21)
#define DEVICE_ID 2

static inline void dwt_enable_all(void) {
    DEMCR |= DEMCR_TRCENA;
    DWT_LAR = 0xC5ACCE55;

    DWT_CYCCNT = 0;
    DWT_CPICNT = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT = 0;
    DWT_FOLDCNT = 0;

    DWT_CTRL |= DWT_CTRL_CYCCNTENA |
                DWT_CTRL_CPIEVTENA |
                DWT_CTRL_SLEEPEVTENA |
                DWT_CTRL_LSUEVTENA |
                DWT_CTRL_FOLDEVTENA;
}

// ============================================================
//  USB wait
// ============================================================
static void wait_for_usb(void) {
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(200);
}

// ============================================================
//  FFT implementation (radix-2)
// ============================================================
#define FFT_N   256
#define FS_HZ   250.0f
#define MEM_MAX 4096

typedef struct { float r, i; } complex_t;

static inline complex_t c_add(complex_t a, complex_t b) {
    return (complex_t){a.r + b.r, a.i + b.i};
}
static inline complex_t c_sub(complex_t a, complex_t b) {
    return (complex_t){a.r - b.r, a.i - b.i};
}
static inline complex_t c_mul(complex_t a, complex_t b) {
    return (complex_t){a.r*b.r - a.i*b.i, a.r*b.i + a.i*b.r};
}

static complex_t fft_buf[FFT_N];
static float mag[FFT_N/2];
static volatile uint8_t mem_buf[MEM_MAX];

void fft(complex_t *buf, int n) {
    int i, j, k, m;
    for (i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j |= bit;
        if (i < j) {
            complex_t tmp = buf[i];
            buf[i] = buf[j];
            buf[j] = tmp;
        }
    }
    for (m = 1; m < n; m <<= 1) {
        float ang = -M_PI / m;
        complex_t wm = {cosf(ang), sinf(ang)};
        for (k = 0; k < n; k += (m << 1)) {
            complex_t w = {1, 0};
            for (j = 0; j < m; j++) {
                complex_t t = c_mul(w, buf[k + j + m]);
                complex_t u = buf[k + j];
                buf[k + j]     = c_add(u, t);
                buf[k + j + m] = c_sub(u, t);
                w = c_mul(w, wm);
            }
        }
    }
}

// ============================================================
//  Utilities
// ============================================================
static inline float frand01(void) {
    return (float)(rand() & 0x7FFF) / 32767.0f;
}

static void generate_healthcare_raw(void) {
    float f_ecg   = 1.1f + 0.4f * frand01();
    float f_trem  = 4.0f + 4.0f * frand01();
    float a_trem  = 0.05f + 0.35f * frand01();
    float a_mains = 0.10f + 0.10f * frand01();
    float a_noise = 0.02f + 0.05f * frand01();

    for (int i = 0; i < FFT_N; i++) {
        float t = (float)i / FS_HZ;
        float ecg   = 0.6f * sinf(2*M_PI*f_ecg*t);
        float trem  = a_trem * sinf(2*M_PI*f_trem*t);
        float mains = a_mains * sinf(2*M_PI*50.0f*t);
        float noise = (2.0f * frand01() - 1.0f) * a_noise;
        fft_buf[i].r = ecg + trem + mains + noise;
        fft_buf[i].i = 0.0f;
    }
}

static void compute_magnitude(void) {
    for (int k = 0; k < FFT_N/2; k++) {
        float re = fft_buf[k].r;
        float im = fft_buf[k].i;
        mag[k] = sqrtf(re*re + im*im);
    }
}

static float band_energy(float f_lo, float f_hi) {
    int k_lo = (int)(f_lo * FFT_N / FS_HZ);
    int k_hi = (int)(f_hi * FFT_N / FS_HZ);
    if (k_lo < 0) k_lo = 0;
    if (k_hi > FFT_N/2-1) k_hi = FFT_N/2-1;
    float e = 0;
    for (int k = k_lo; k <= k_hi; k++) e += mag[k]*mag[k];
    return e;
}

// ============================================================
//  Workloads
// ============================================================
void workload_light(void) {
    generate_healthcare_raw();
    int passes = 1 + rand()%2;
    for (int i=0;i<passes;i++) fft(fft_buf, FFT_N);
    compute_magnitude();
    volatile float e1 = band_energy(0.1f, 0.8f);
    volatile float e2 = band_energy(3.0f, 10.0f);
    volatile float e3 = band_energy(45.0f, 55.0f);
    __asm volatile(""::"r"(e1),"r"(e2),"r"(e3):"memory");
}

void workload_medium(void) {
    generate_healthcare_raw();
    int passes = 2 + rand()%2;
    for (int i=0;i<passes;i++) fft(fft_buf, FFT_N);
    compute_magnitude();

    float e1 = band_energy(0.1f, 0.8f);
    float e2 = band_energy(0.8f, 3.0f);
    float e3 = band_energy(3.0f, 10.0f);

    volatile float sm = 0;
    for (int i=0;i<300;i++) sm = 0.9f*sm + 0.1f*(e2 + e3);

    int mem = 1024 + rand()%1024;
    for (int i=0;i<mem;i++) mem_buf[i] ^= i;

    __asm volatile(""::"r"(sm):"memory");
}

void workload_heavy(void) {
    generate_healthcare_raw();
    int passes = 3 + rand()%3;
    for (int i=0;i<passes;i++) fft(fft_buf, FFT_N);
    compute_magnitude();

    float e1 = band_energy(0.1f, 0.8f);
    float e2 = band_energy(0.8f, 3.0f);
    float e3 = band_energy(3.0f, 10.0f);
    float e4 = band_energy(10.0f, 40.0f);

    volatile float score = 0;
    for (int i=0;i<800;i++) {
        if (i & 1) score += e3 / (e2 + 1e-6f);
        else       score += e4 / (e2 + 1e-6f);
        score *= 0.99f;
    }

    int mem = 2048 + rand()%2048;
    for (int i=0;i<mem;i++) mem_buf[i] ^= (i*13);

    __asm volatile(""::"r"(score):"memory");
}

// ============================================================
//  Benchmark harness
// ============================================================
#define REPEATS 100

void benchmark(void (*fn)(void), int id, int label) {
    double sumC=0, sumL=0, sumP=0, sumF=0, sumT=0;
    double sqC=0, sqL=0, sqP=0, sqF=0, sqT=0;

    for (int r=0; r<REPEATS; r++) {
        dwt_enable_all(); // Μηδενίζει και ενεργοποιεί τους counters
        
        uint64_t t0 = time_us_64();
        fn();
        uint64_t t1 = time_us_64();

        // Αποθήκευση αμέσως μετά την εκτέλεση
        uint32_t C = DWT_CYCCNT;
        uint32_t L = DWT_LSUCNT;
        uint32_t P = DWT_CPICNT;
        uint32_t F = DWT_FOLDCNT;
        uint32_t T = (uint32_t)(t1 - t0);

        sumC += C; sqC += (double)C*C;
        sumL += L; sqL += (double)L*L;
        sumP += P; sqP += (double)P*P;
        sumF += F; sqF += (double)F*F;
        sumT += T; sqT += (double)T*T;
    }

    double mC=sumC/REPEATS, mL=sumL/REPEATS, mP=sumP/REPEATS;
    double mF=sumF/REPEATS, mT=sumT/REPEATS;

    double sC=sqrt(fabs(sqC/REPEATS - mC*mC));
    double sL=sqrt(fabs(sqL/REPEATS - mL*mL));
    double sP=sqrt(fabs(sqP/REPEATS - mP*mP));
    double sF=sqrt(fabs(sqF/REPEATS - mF*mF));
    double sT=sqrt(fabs(sqT/REPEATS - mT*mT));

    // ΔΙΟΡΘΩΜΕΝΟ PRINTF (13 ορίσματα για 13 στήλες)
    printf("%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d\n",
            DEVICE_ID, id, mC, sC, mL, sL, mP, sP, mF, sF, mT, sT, label);
}

// ============================================================
//  Main
// ============================================================
int main(void) {
    stdio_init_all();
    wait_for_usb();
    srand(time_us_64());

    printf("device id, signal,meanC,stdC,meanL,stdL,meanP,stdP,meanF,stdF,meanT,stdT,label\n");

    int NUM = 300;
    for (int i=0;i<NUM;i++) benchmark(workload_light,  i, 0);
    for (int i=0;i<NUM;i++) benchmark(workload_medium, i, 1);
    for (int i=0;i<NUM;i++) benchmark(workload_heavy,  i, 2);

    while (true) sleep_ms(2000);
}
