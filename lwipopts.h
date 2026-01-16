#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

#define NO_SYS 1

// --- core protocols ---
#define LWIP_IPV4 1
#define LWIP_TCP  1
#define LWIP_UDP  1
#define LWIP_DHCP 1
#define LWIP_DNS  1

// --- IMPORTANT: disable netconn/sockets ---
#define LWIP_NETCONN 0
#define LWIP_SOCKET  0

// --- memory (safe defaults) ---
#define MEM_ALIGNMENT 4
#define MEM_SIZE (16 * 1024)

#define PBUF_POOL_SIZE 16
#define PBUF_POOL_BUFSIZE 1700

#define MEMP_NUM_TCP_PCB 8
#define MEMP_NUM_TCP_SEG 32
#define MEMP_NUM_SYS_TIMEOUT 8

#define LWIP_STATS 0

#endif
