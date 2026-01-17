# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================

set(PICO_BOARD pico2_w CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(pico-benchmark C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

#   WIFI VARIABLES 
# ---- WiFi / Verifier settings (CMake cache vars) ----
set(WIFI_SSID "" CACHE STRING "WiFi SSID (2.4GHz)")
set(WIFI_PASSWORD "" CACHE STRING "WiFi password")
set(VERIFIER_IP "" CACHE STRING "Verifier PC IPv4, e.g. 192.168.68.123")
set(VERIFIER_PORT 4242 CACHE STRING "Verifier TCP port")


# Add executable. Default name is the project name, version 0.1

add_executable(pico-benchmark pico-benchmark.c )

pico_set_program_name(pico-benchmark "pico-benchmark")
pico_set_program_version(pico-benchmark "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(pico-benchmark 0)
pico_enable_stdio_usb(pico-benchmark 1)

# Add the standard library to the build
target_link_libraries(pico-benchmark
        pico_stdlib)

# Add the standard include files to the build
target_include_directories(pico-benchmark PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

# Add any user requested libraries
target_link_libraries(pico-benchmark 
        
        )

pico_add_extra_outputs(pico-benchmark)

# ---------------------------------------------------------
# ΝΕΟ EXECUTABLE ΓΙΑ ΤΟ HEALTHCARE FFT BENCHMARK
# ---------------------------------------------------------
add_executable(fft_benchmark
    fft_benchmark.c
)

target_link_libraries(fft_benchmark
    pico_stdlib
)

# Add the standard include files to the build
target_include_directories(fft_benchmark PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)
pico_enable_stdio_uart(fft_benchmark 0)
pico_enable_stdio_usb(fft_benchmark 1)

pico_add_extra_outputs(fft_benchmark)

# ---------------------------------------------------------
# ΝΕΟ EXECUTABLE ΓΙΑ ΤΟ MOVING AVERAGE BENCHMARK
# ---------------------------------------------------------

add_executable(ma_benchmark
    ma_benchmark.c
)

target_link_libraries( ma_benchmark pico_stdlib)
pico_enable_stdio_usb( ma_benchmark 1)
pico_enable_stdio_uart( ma_benchmark 0)
pico_add_extra_outputs( ma_benchmark)

# ---------------------------------------------------------
# ΝΕΟ EXECUTABLE ΓΙΑ ΤΟ LOW PASS FILTER BENCHMARK
# ---------------------------------------------------------
add_executable(lp_benchmark
   lp_benchmark.c
)

target_link_libraries( lp_benchmark pico_stdlib)
pico_enable_stdio_usb( lp_benchmark 1)
pico_enable_stdio_uart(lp_benchmark 0)
pico_add_extra_outputs(lp_benchmark)


# ---------------------------------------------------------
# ΝΕΟ EXECUTABLE ΓΙΑ ΤΟ SEIZURE BENCHMARK
# ---------------------------------------------------------
add_executable(seizure_benchmark
 seizure_benchmark.c
)

target_link_libraries(seizure_benchmark pico_stdlib)
pico_enable_stdio_usb(seizure_benchmark 1)
pico_enable_stdio_uart(seizure_benchmark 0)
pico_add_extra_outputs(seizure_benchmark)

add_executable(lp_benchmark_injection_static
 lp_benchmark_injection_static.c
)

target_link_libraries(lp_benchmark_injection_static pico_stdlib)
pico_enable_stdio_usb(lp_benchmark_injection_static 1)
pico_enable_stdio_uart(lp_benchmark_injection_static 0)
pico_add_extra_outputs(lp_benchmark_injection_static)


add_executable(lp_dynamic_injection
 lp_dynamic_injection.c
)

target_link_libraries(lp_dynamic_injection pico_stdlib)
pico_enable_stdio_usb(lp_dynamic_injection 1)
pico_enable_stdio_uart(lp_dynamic_injection 0)
pico_add_extra_outputs(lp_dynamic_injection)

add_executable(lp_dos
 lp_dos.c
)

target_link_libraries(lp_dos pico_stdlib)
pico_enable_stdio_usb(lp_dos 1)
pico_enable_stdio_uart(lp_dos 0)
pico_add_extra_outputs(lp_dos)

add_executable(lp_rop
 lp_rop.c
)

target_link_libraries(lp_rop pico_stdlib)
pico_enable_stdio_usb(lp_rop 1)
pico_enable_stdio_uart(lp_rop 0)
pico_add_extra_outputs(lp_rop)


add_executable(lp_every_100ms
 lp_every_100ms.c
)

target_link_libraries(lp_every_100ms pico_stdlib)
pico_enable_stdio_usb(lp_every_100ms 1)
pico_enable_stdio_uart(lp_every_100ms 0)
pico_add_extra_outputs(lp_every_100ms)

add_executable(fft_every_100ms
 fft_every_100ms.c
)

target_link_libraries(fft_every_100ms pico_stdlib)
pico_enable_stdio_usb(fft_every_100ms 1)
pico_enable_stdio_uart(fft_every_100ms 0)
pico_add_extra_outputs(fft_every_100ms)

add_executable(ma_every_100ms
 ma_every_100ms.c
)

target_link_libraries(ma_every_100ms pico_stdlib)
pico_enable_stdio_usb(ma_every_100ms 1)
pico_enable_stdio_uart(ma_every_100ms 0)
pico_add_extra_outputs(ma_every_100ms)

add_executable(seizure_every_100ms
 seizure_every_100ms.c
)

target_link_libraries(seizure_every_100ms pico_stdlib)
pico_enable_stdio_usb(seizure_every_100ms 1)
pico_enable_stdio_uart(seizure_every_100ms 0)
pico_add_extra_outputs(seizure_every_100ms)

add_executable(lp_every_100ms_with_rop
 lp_every_100ms_with_rop.c
)

target_link_libraries(lp_every_100ms_with_rop pico_stdlib)
pico_enable_stdio_usb(lp_every_100ms_with_rop 1)
pico_enable_stdio_uart(lp_every_100ms_with_rop 0)
pico_add_extra_outputs(lp_every_100ms_with_rop)


# ---------------------------------------------------------
# ΝΕΟ EXECUTABLE: LP EVERY 100ms + WiFi prover (verifier comm)
# ---------------------------------------------------------
add_executable(lp_every_100ms_wifi
    lp_every_100ms_wifi.c
    sha256.c
)

target_link_libraries(lp_every_100ms_wifi
    pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background
    hardware_timer
    hardware_sync
)

target_include_directories(lp_every_100ms_wifi PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
)

pico_enable_stdio_usb(lp_every_100ms_wifi 1)
pico_enable_stdio_uart(lp_every_100ms_wifi 0)

target_compile_definitions(lp_every_100ms_wifi PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    VERIFIER_IP=\"${VERIFIER_IP}\"
    VERIFIER_PORT=${VERIFIER_PORT}
)

pico_add_extra_outputs(lp_every_100ms_wifi)

