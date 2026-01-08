#include "pico/stdlib.h"
#include <stdio.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
//  ARM Cortex-M33 DWT register definitions
// -----------------------------------------------------------------------------
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

// -----------------------------------------------------------------------------
//  Utility: Enable all DWT counters
// -----------------------------------------------------------------------------
static inline void dwt_enable_all(void) {
    DEMCR |= DEMCR_TRCENA;     // enable trace
    DWT_LAR = 0xC5ACCE55;      // unlock

    // reset all counters
    DWT_CYCCNT = 0;
    DWT_CPICNT = 0;
    DWT_EXCCNT = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT = 0;
    DWT_FOLDCNT = 0;

    // start + enable all event counters
    DWT_CTRL |= DWT_CTRL_CYCCNTENA |
                DWT_CTRL_CPIEVTENA |
                DWT_CTRL_EXCEVTENA |
                DWT_CTRL_SLEEPEVTENA |
                DWT_CTRL_LSUEVTENA |
                DWT_CTRL_FOLDEVTENA;
}

// -----------------------------------------------------------------------------
//  Workload (replace this with your attestation tasks)
// -----------------------------------------------------------------------------
void workload_heavy(void) {
    volatile float sum = 0;
    for (volatile uint32_t i = 0; i < 200000; i++) {
        sum += i * 1.001f;
    }
}

void workload_light(void) {
    volatile uint32_t acc = 0;
    for (volatile uint32_t i = 0; i < 50000; i++) {
        acc += (i ^ 0x1234);
    }
}

// -----------------------------------------------------------------------------
//  Helper: wait until USB is ready
// -----------------------------------------------------------------------------
void wait_for_usb_connection() {
    while (!stdio_usb_connected()) {
        sleep_ms(100);
    }
    sleep_ms(200);
}

// -----------------------------------------------------------------------------
//  Run one benchmark
// -----------------------------------------------------------------------------
void run_benchmark(const char *label, void (*fn)(void)) {
    printf("\n=== Running: %s ===\n", label);

    dwt_enable_all();
    uint64_t start_us = time_us_64();

    fn();

    uint64_t end_us = time_us_64();

    uint32_t cycles  = DWT_CYCCNT;
    uint32_t cpi     = DWT_CPICNT;
    uint32_t exc     = DWT_EXCCNT;
    uint32_t sleep   = DWT_SLEEPCNT;
    uint32_t lsu     = DWT_LSUCNT;
    uint32_t fold    = DWT_FOLDCNT;

    printf("Time (us):     %llu\n", (end_us - start_us));
    printf("Cycles:        %lu\n",   (unsigned long)cycles);
    printf("CPI stalls:    %lu\n",   (unsigned long)cpi);
    printf("LSU stalls:    %lu\n",   (unsigned long)lsu);
    printf("Folded instr:  %lu\n",   (unsigned long)fold);
    printf("Sleep cycles:  %lu\n",   (unsigned long)sleep);
    printf("Exceptions:    %lu\n",   (unsigned long)exc);

    // Composite metrics
    float active_ratio = 1.0f - ((float)sleep / (float)(cycles + 1));
    float mem_stress   = (float)lsu / (float)(cycles + 1);
    printf("Active ratio:  %.3f\n", active_ratio);
    printf("Mem stress:    %.3f\n", mem_stress);
    printf("==========================\n");
}

// -----------------------------------------------------------------------------
//  Main
// -----------------------------------------------------------------------------
int main(void) {
    stdio_init_all();
    wait_for_usb_connection();

    printf("\nPico 2 W — Full Performance Benchmark\n");

    run_benchmark("Light Workload", workload_light);
    sleep_ms(500);
    run_benchmark("Heavy Workload", workload_heavy);

    printf("\nAll benchmarks complete.\n");

    while (true) {
        sleep_ms(1000);
    }
}
