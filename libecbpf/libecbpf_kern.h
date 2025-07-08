
#ifndef __LIBECBPF_KERN_H
#define __LIBECBPF_KERN_H

/* 
 * Header for EC BPF programs
 */
#include "rootmaps.h"
#include "xdp_sampler.h"
#include "xdp_return_codes.h"
#include <stdint.h>

struct vlan_hdr {
    uint16_t  h_vlan_TCI;
    uint16_t  h_vlan_encapsulated_proto;
};

#ifdef NDEBUG // Release mode, follows C convention from assert.h
#define bpf_debug(fmt, ...) ((void) 0)
#else
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 * From kernel/samples/bpf/bpf_tail_calls01_kern.c
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt "\n";				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#endif

static __always_inline void update_stat_counters(xdpcap_retval_t *result) {
	void *valuep;

	if (XDP_PROG_ARRAY_IDX < 0)
		return;

	__u32 key = XDP_PROG_ARRAY_IDX;

	// normalize result
	if (result->action < STAT_XDP_ABORTED || result->action > STAT_XDP_REDIRECT)
		result->action = STAT_XDP_INVALID_ACTION;

	// Map is to be populated by xdp_root_loader
	valuep = bpf_map_lookup_elem(&XDP_STATS_MAP_NAME, &key);
	if (valuep && (result->action >= 0 && result->action < STAT_XDP_MAX)) {
		((struct xdp_stats *) valuep)->action_count[result->action]++;
		bpf_debug("update_stat_counters: slot %i act %i to %i", XDP_PROG_ARRAY_IDX, result->action,
			  ((struct xdp_stats *) valuep)->action_count[result->action]);
	} else {
		bpf_debug("update_stat_counters: element not found or action index out of bounds!?");
	}
}

/* bpf_tail_call is smart and will return if the slot in the
 * map is not valid.  So we iterate until hitting a program fd
 * or just return XDP_PASS.
 */
#define CALL_NEXT()                             \
    do { \
    _Pragma("unroll") \
    for (__u32 i = (XDP_PROG_ARRAY_IDX + 1); i < SUBPROGRAM_MAX; i++) { \
        bpf_tail_call(ctx, &ROOT_MAP_NAME, i); \
    } \
    } while(0);

/*
 * Support for Cloudflare's xdpcap software
 * and collect some statistics.
 */
#define XDPCAP_RETURN(ctx, retval) \
  do { \
  update_stat_counters(&retval); \
  ecbpf_sample_packet(ctx, XDP_PROG_ARRAY_IDX, &retval); \
  bpf_tail_call(ctx, &XDPCAP_MAP_NAME, retval.action); \
  return retval.action; \
  } while(0);

#endif // __LIBECBPF_KERN_H
