#ifndef _XDP_ROOT_SAMPLER
#define _XDP_ROOT_SAMPLER 1

#include "xdp_sampler_client.h"
#include "xdp_return_codes.h"
#include <stdint.h>
#include <limits.h>

#define XDP_SAMPLER_RATE 2500u

#define MAX_CPUS 128
#define MAGIC 0xf00d

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef ECBPF_KERN // Definitions for BPF programs

/* XXX: Keep in sync with userland version below */
struct  __attribute__((packed)) xdp_sample_metadata {
	uint16_t cookie;
	uint32_t len;
	uint32_t caplen;
	uint32_t sampling_probability_reciprocal;
    int32_t xdp_action_source; // XDP program slot for now.  Root array is -1 in ecbpf-land.
	int32_t xdp_action;
	uint32_t xdp_action_code;
    uint64_t xdp_action_meta;
};

static void ecbpf_sample_packet(struct xdp_md *ctx, int xdp_action_source, 
	xdpcap_retval_t *result) {
	uint32_t rand;
	__u64 flags = BPF_F_CURRENT_CPU;
	struct xdp_sample_metadata metadata = {};
	int ret = 0;
	rand = bpf_get_prandom_u32();

	if (rand > (UINT_MAX/XDP_SAMPLER_RATE))
		return;

	// Sample the packet
	__builtin_memset(&metadata, 0, sizeof(metadata));  // Verifier will complain about padding not zero'd
													   // at bpf_perf_event_output call time
	metadata.cookie = MAGIC;
	metadata.len = ctx->data_end - ctx->data;
	metadata.caplen = MIN(metadata.len, XDP_SAMPLER_CAPLEN);
	metadata.sampling_probability_reciprocal = XDP_SAMPLER_RATE; // This may vary at Muzammil's request
	metadata.xdp_action_source = xdp_action_source;
	metadata.xdp_action = result->action;
	metadata.xdp_action_code = result->code;
	metadata.xdp_action_meta = result->meta;

	/* From linux/samples/bpf/xdp_sample_pkts_kern.c:
	 *
	 * The XDP perf_event_output handler will use the upper 32 bits
	 * of the flags argument as a number of bytes to include of the
	 * packet payload in the event data. If the size is too big, the
	 * call to bpf_perf_event_output will fail and return -EFAULT.
	 *
	 * See bpf_xdp_event_output in net/core/filter.c.
	 *
	 * The BPF_F_CURRENT_CPU flag means that the event output fd
	 * will be indexed by the CPU number in the event map.
	 */
	flags |= (__u64)metadata.caplen << 32;

	ret = bpf_perf_event_output(ctx, &XDP_SAMPLER_MAP_NAME, flags,
					&metadata, sizeof(metadata));

	/* XXX: This will taint a production kernel
	if (ret)
		bpf_printk("perf_event_output failed: %d\n", ret); // We get -2 if nothing is monitoring the perf buffer
	else
		bpf_printk("perf_event_output success\n");
	*/
}

#else // Userspace Definitions

#define SEC(x)

/* XXX: Keep in sync with kernel version above */
struct __attribute__((packed)) xdp_sample_metadata {
	uint16_t cookie;
	uint32_t len; // Length of the original packet
	uint32_t caplen; // Number of bytes available (length of pkt_data)
	uint32_t sampling_probability_reciprocal;
    int32_t xdp_action_source; // XDP program slot for now.  Root array is -1 in ecbpf-land.
	int32_t xdp_action;
    uint32_t xdp_action_code;
    uint64_t xdp_action_meta;
	uint8_t  pkt_data[XDP_SAMPLER_CAPLEN];
};

#endif // ECBPF_KERN
#endif // _XDP_ROOT_SAMPLER
