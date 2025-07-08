/*
 * Root XDP program
 */
#define ECBPF_KERN

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#define XDP_PROG_ARRAY_IDX XDP_ROOT_IDX
#include "libecbpf_kern.h"


SEC("xdp")
int ROOT_PROG_NAME(struct xdp_md *ctx)
{
	uint16_t eth_proto;
	xdpcap_retval_t retval = {XDP_PASS, XDP_CODE_MU, 0x00};

	void *ptr = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = ptr;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;

	// If we don't have a IP/IPv6 TCP, UDP, or ICMP packet, pass it to the kernel right away.
	if ((void *)(eth + 1) > end) {
			retval.code = XDP_CODE_ETH_LEN_ERR;
			retval.action = XDP_ABORTED;
			goto done;
	}

	ptr += sizeof(struct ethhdr);

	/* For now, just pass tagged packets to the kernel.  The tagged VLAN10 is for outgoing 
	   and we should ignore any incoming traffic on VLAN10.
	*/
	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP):
		iph = ptr;
		if ( (void *)(iph + 1) > end) {
			retval.code = XDP_CODE_IP_LEN_ERR;
			retval.action = XDP_ABORTED;
			goto done;
		}

		switch (iph->protocol) {
			case IPPROTO_UDP:
			case IPPROTO_ICMP:
			case IPPROTO_TCP:
				goto next;
			default:
				retval.code = XDP_CODE_IP_UNSUPP_PROTO;
				goto done;
		};

	case bpf_htons(ETH_P_IPV6):
		ip6h = ptr;
		if( (void *)(ip6h + 1) > end) {
			retval.code = XDP_CODE_IP6_LEN_ERR;
			retval.action = XDP_ABORTED;
			goto done;
		}

		switch (ip6h->nexthdr) {
			case IPPROTO_UDP:
			case IPPROTO_ICMPV6:
			case IPPROTO_TCP:
				goto next;
			default:
				retval.code = XDP_CODE_IP6_UNSUPP_PROTO;
				goto done;
		};
	default:
		// important to pass here for ARP, 802.1Q
		retval.code = XDP_CODE_NON_IP;
		goto done;
	}


next: // Cycle through the root array
	CALL_NEXT();
done: // Exit out of XDP
	XDPCAP_RETURN(ctx, retval);	// Let the kernel handle the packet if no maps are present
}

char _license[] SEC("license") = "APL";
