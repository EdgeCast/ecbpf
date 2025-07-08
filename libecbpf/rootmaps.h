#ifndef __LIBECBPF_ROOTMAPS_H
#define __LIBECBPF_ROOTMAPS_H

#include "xdp_stats.h"

#define SUBPROGRAM_MAX 8 // Slots allocated in the root program array

#define ROOT_PROG_NAME xdp_root_prog
#define ROOT_PROG_NOP_NAME xdp_root_nop
#define ROOT_MAP_NAME xdp_program_array
#define XDPCAP_MAP_NAME xdpcap_hook
#define XDP_STATS_MAP_NAME xdp_stats
#define XDP_SAMPLER_MAP_NAME packet_samples
#define MAX_CPUS 128

// expand macros into quoted strings
#define xstr(s) str(s)
#define str(s) #s

/*
 * Slot Definitions for XDP_PROG_ARRAY_NAME -> slot number
 */
enum prog_array_idxs {
	XDP_ROOT_IDX = -1, // Make CALL_NEXT work properly for root array
	XDP_SAMPLER_IDX = 1,
	XDP_FILTER_IDX = 2,
	XDP_FW_IDX = 5,
	XDP_PRINTK_IDX = 6,
	XDP_IPVS_BYPASS_IDX = 7,
};

#ifdef ECBPF_KERN // Definitions for BPF programs

#ifndef XDP_PROG_ARRAY_IDX
#error You must define a XDP_PROG_ARRAY_IDX that is in the enum prog_array_idxs
#endif // XDP_PROG_ARRAY_NAME

#include <bpf_helpers.h> // __uint and __type macros

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SUBPROGRAM_MAX);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} ROOT_MAP_NAME SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 5);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} XDPCAP_MAP_NAME SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SUBPROGRAM_MAX);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct xdp_stats));
} XDP_STATS_MAP_NAME SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(uint32_t));
	__uint(max_entries, MAX_CPUS);
} XDP_SAMPLER_MAP_NAME SEC(".maps");

#else // Userspace Definitions

#endif // ECBPF_KERN

#endif // __LIBECBPF_ROOTMAPS_H
