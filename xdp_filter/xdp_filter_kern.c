/*
 * Proof of concept to filter IP fragments and source drop.  IP
 * fragments destined to a VIP can't be handled properly because
 * they arrive at different directors.  We have seen customer DDOS stress
 * tests that also involved sending lots of fragments.
 *
 * One issue that needs to be resolved is locally destined fragments.
 * Right now ack fast path contains information about which IPs are local,
 * but we should see if we can make that generally available.  Perhaps
 * flag a packet as local in the root array using XDP metadata?
 */

#define ECBPF_KERN

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include "xdp_filter.h"
#include "libecbpf_kern.h"

#define ICMP_REPLY_SIZE 36 // icmp + ip + 8 bytes

int send_packet_too_big(struct xdp_md *ctx, struct filter_state *state, xdpcap_retval_t *retval) {
	struct iphdr *inner_iphdr, *outer_iphdr;
	struct ethhdr *inner_ethhdr, *outer_ethhdr;
	struct icmphdr *icmphdr;
	__u32 csum = 0;

	// Make the verifier happy
	if (!retval)
		return -1;

	if (!state) {
		retval->code = XDP_CODE_VERIFIER_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	int packet_size = ctx->data_end - ctx->data; // This will be the size of the min ethernet frame...
	int orig_size = packet_size - ETH_HLEN;
	int payload_size = packet_size - (ETH_HLEN + (int)sizeof(struct iphdr));
	int head = (int)sizeof(struct icmphdr) + (int)sizeof(struct iphdr);
	int decrease = 0;

	bpf_debug("xdp_filter: First fragment length: %d payload length: %d", packet_size, payload_size);

	// Trim the head and the tail up front since the pointers can change.
	if (bpf_xdp_adjust_head(ctx, 0 - head)) {
		bpf_debug("xdp_filter: Failed to allocate headroom to encapsulate reply");
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_ADJ_HEAD_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	} else {
		bpf_debug("xdp_filter: Adjusted head by %d", 0 - head);
		packet_size += head;
	}

	// Trim the payload
	if (payload_size > 8) {
		decrease = 8 - payload_size;
		if (bpf_xdp_adjust_tail(ctx, decrease)) {
			bpf_debug("xdp_filter: Failed to reduce payload size by %d", decrease);
			state->ptb_mem_err_count++;
			retval->code = XDP_CODE_ADJ_TAIL_ERR;
			retval->action = XDP_ABORTED;
			return -1;
		} else {
			bpf_debug("xdp_filter: Reduced payload size by %d", decrease);
			packet_size += decrease;
		}
	}

	outer_ethhdr = (struct ethhdr*) (void *)(long)ctx->data;
	if ((void *) (outer_ethhdr+1) > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	inner_ethhdr = (struct ethhdr*) ((void *)(long)ctx->data + head);
	if ((void *) (inner_ethhdr+1) > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	inner_iphdr = (struct iphdr*) (void *)(inner_ethhdr + 1);
	if ((void *) (inner_iphdr+1) > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	outer_iphdr = (struct iphdr*) (void *)(outer_ethhdr+1);
	if ((void *) (outer_iphdr+1) > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	icmphdr = (struct icmphdr*) (void *)(outer_iphdr + 1);
	if ((void *) (icmphdr+1) > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	// Populate the new eth hdr
	memcpy(outer_ethhdr->h_dest, inner_ethhdr->h_source, ETH_ALEN);
	memcpy(outer_ethhdr->h_source, inner_ethhdr->h_dest, ETH_ALEN);
	outer_ethhdr->h_proto = bpf_htons(ETH_P_IP);

	// Populate the new ip hdr
	outer_iphdr->version = 4;
	outer_iphdr->ihl = 5;
	outer_iphdr->tos = 0;
	outer_iphdr->tot_len = bpf_htons(packet_size - ETH_HLEN);
	outer_iphdr->id = 0;
	outer_iphdr->frag_off = 0;
	outer_iphdr->ttl = 128;
	outer_iphdr->protocol = IPPROTO_ICMP;
	outer_iphdr->check = 0;
	outer_iphdr->saddr = inner_iphdr->daddr;
	outer_iphdr->daddr = inner_iphdr->saddr;

	csum = 0;
	__u16 *iph_chunk = (__u16*) outer_iphdr;
	for (int i = 0; i < outer_iphdr->ihl * 2; i++) {
		csum += *iph_chunk;
		iph_chunk++;
	}

	csum =  (csum & 0xffff) + (csum >> 16);
	if (csum>>16) {
		csum =  (csum & 0xffff) + (csum >> 16);
	}

	outer_iphdr->check =  ~csum;

	// Populate the icmp header
	icmphdr->type = ICMP_DEST_UNREACH;
	icmphdr->code = ICMP_FRAG_NEEDED;
	icmphdr->un.frag.mtu = bpf_htons(orig_size);
	icmphdr->checksum = 0;

	csum = 0;
	__u16 *icmp_chunk = (__u16*) icmphdr;
	if (((void *) (icmphdr)) + ICMP_REPLY_SIZE > (void *)(long)ctx->data_end) {
		state->ptb_mem_err_count++;
		retval->code = XDP_CODE_FILTER_PTB_VERIFY_ERR;
		retval->action = XDP_ABORTED;
		return -1;
	}

	for (int i = 0; i < ICMP_REPLY_SIZE/2; i++) {
		csum += icmp_chunk[i];
	}
	csum =  (csum & 0xffff) + (csum >> 16);
	if (csum>>16) {
		csum =  (csum & 0xffff) + (csum >> 16);
	}

	icmphdr->checksum = ~csum;

	bpf_debug("xdp_filter: Launching response!");
	
	return 0;
}

bool ip_addr_drop(uint32_t addr) {
	void *valuep;

	static struct ip_trie_key key;
	struct filter_drop_entry *entry;

	key.key = addr;
	key.prefix_len = 32;

	valuep = bpf_map_lookup_elem(&XDP_FILTER_IP_MAP, &key);

	if (valuep) {
		entry = (struct filter_drop_entry *) valuep;
		bpf_debug("xdp_filter: addr: %x found in IP drop map.", bpf_htonl(addr));

		return true;
	}

	bpf_debug("xdp_filter: addr: %x not in map", bpf_htonl(addr));
	return false;
}

bool ip6_addr_drop(struct in6_addr *addr) {
	void *valuep;

	static struct ip6_trie_key key;
	struct filter_drop_entry *entry;

	key.prefix_len = 128;
	key.addr6 = *addr;

	valuep = bpf_map_lookup_elem(&XDP_FILTER_IP6_MAP, &key);

	if (valuep) {
		entry = (struct filter_drop_entry *) valuep;

		// We can't pass more than 5 args because bpf (the macro hides a sizeof the format string)
		bpf_debug("xdp_filter: addr6 %x:...:%x found in drop map.",
        		bpf_htonl(addr->s6_addr32[0]),
        		bpf_htonl(addr->s6_addr32[3]));

		return true;
	}

	// We can't pass more than 5 args because bpf (the macro hides a sizeof the format string)
	bpf_debug("xdp_filter: addr6 %x:...:%x not found in drop map.",
		bpf_htonl(addr->s6_addr32[0]),
		bpf_htonl(addr->s6_addr32[3]));

	return false;
}

SEC("xdp")
int XDP_FILTER_PROG_NAME(struct xdp_md *ctx)
{
	uint64_t curr_time_ns;
	uint16_t eth_proto;
	xdpcap_retval_t retval = {XDP_PASS, XDP_CODE_MU, 0x00};
	void *layer = (void*) (long)ctx->data;
	void *data_end = (void*) (long)ctx->data_end;
	struct ethhdr *eth = layer;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct filter_configuration *config = NULL;
	struct filter_state *state = NULL;
	int idx = 0;

	int frag_offset = 0;
	bool frag_mf_flag = false;

	// Look up configuration
	config = (struct filter_configuration *) bpf_map_lookup_elem(&XDP_FILTER_CONFIG_MAP, &idx);

	if (!config) {
		bpf_debug("xdp_filter: pass: no configuration record");
		retval.code = XDP_CODE_MAP_ERR;
		retval.action = XDP_PASS;
		goto done; // Don't drop on internal failure
	}

	// Look up state
	state = (struct filter_state *) bpf_map_lookup_elem(&XDP_FILTER_STATE_MAP, &idx);

	if (!state) {
		bpf_debug("xdp_filter: pass: no state record");
		retval.code = XDP_CODE_MAP_ERR;
		retval.action = XDP_PASS;
		goto done; // Don't drop on internal failure
	}

	// Sanity check ethernet header
	if ((void *)(eth + 1) > data_end) {
		bpf_debug("xdp_filter: abort: truncated ethernet header");
		state->eth_frame_err++;
		retval.code = XDP_CODE_ETH_LEN_ERR;
		retval.action = XDP_ABORTED;
		goto done;
	}

	// Swtich based on eth proto
	switch (bpf_ntohs(eth->h_proto)) {
		case ETH_P_IP:
			// Carry on with IP decoding.  Should probably break it out into
			// a function in the future.
			break;
          	case ETH_P_IPV6:
			ip6h = (struct ipv6hdr *)(eth + 1);
			if ((void *)(ip6h + 1) > data_end) {
				bpf_debug("xdp_filter: abort: truncated ip6 header");
				state->eth_frame_err++;
				retval.code = XDP_CODE_IP6_LEN_ERR;
				retval.action = XDP_ABORTED;
				goto done;
			}
			if(ip6_addr_drop(&ip6h->saddr)) {
				state->ip6_drop_count++;
				retval.code = XDP_CODE_FILTER_IP6_DROP;
				retval.action = XDP_DROP;
				goto done;
			}

			retval.action = XDP_PASS;
			goto done;
			break;
		default:
			bpf_debug("xdp_filter: pass: skipping non ip packet");
			retval.code = XDP_CODE_NON_IP;
			retval.action = XDP_PASS;
			goto done;
			break;
	}

	iph = (struct iphdr *)(eth + 1);

	if ((void *)(iph + 1) > data_end) {
		bpf_debug("xdp_filter: abort: truncated ip header");
		state->eth_frame_err++;
		retval.code = XDP_CODE_IP_LEN_ERR;
		retval.action = XDP_ABORTED;
		goto done;
	}

	// No header options expected
	if (iph->ihl != 5) {
		bpf_debug("xdp_filter: drop: ip options present");
		state->ip_header_err++;
		retval.code = XDP_CODE_FILTER_IP_OPT_DROP;
		retval.action = XDP_DROP;
		goto done;
	}

	// Packet Length
	if (bpf_ntohs(iph->tot_len) + ETH_HLEN > ctx->data_end - ctx->data) {
		bpf_debug("xdp_filter: abort: ip payload length");
		state->ip_header_err++;
		retval.code = XDP_CODE_IP_LEN_ERR;
		retval.action = XDP_ABORTED;
		goto done;
	}

	// Evil bit set
	if (iph->frag_off & bpf_htons(IP_RF)) {
		bpf_debug("xdp_filter: drop: ip evil bit set");
		state->ip_header_err++;
		retval.code = XDP_CODE_FILTER_IP_EVIL_DROP;
		retval.action = XDP_DROP;
		goto done;
	}

	// Check address
	if (ip_addr_drop(iph->saddr)) {
		state->ip_drop_count++;
		retval.code = XDP_CODE_FILTER_IP_DROP;
		retval.action = XDP_DROP;
		goto done;
	}

	// Now check frag
	if (config->frags_drop && iph->frag_off & ~bpf_htons(IP_DF)) {
		frag_offset = bpf_ntohs(iph->frag_off) & IP_OFFMASK;
		frag_mf_flag = iph->frag_off & bpf_htons(IP_MF);
		bpf_debug("xdp_filter: Fragment detected: frag_offset: %d mf: %d", frag_offset, frag_mf_flag);

		// Count frag drops for all frags
		state->ip_frag_drop_count++;

		// Send Packet too big
		if (config->ptb_send  && frag_offset == 0 && frag_mf_flag) {
			// Rate check here
			curr_time_ns = bpf_ktime_get_ns();

			// Are we outside the window?
			if (curr_time_ns - state->ptb_last_sent > 1e9) {
				bpf_debug("xdp_filter: Rate outside of window");
				state->ptb_last_sent = curr_time_ns;
				state->ptb_window_budget = config->ptb_max_pps;
			} else {
				// We are inside the window still, but we don't have a budget
				if (state->ptb_window_budget <= 0) {
					retval.code = XDP_CODE_FILTER_IP_FRAG_DROP;
					retval.action = XDP_DROP;
					goto done;
				}
			}

			// Check that the payload size is sane
			int payload_length = bpf_ntohs(iph->tot_len) - sizeof(struct iphdr);
			if (payload_length < 8 || (payload_length % 8 != 0)) {
				// Bogus first fragment packet
				bpf_debug("xdp_filter: Fragmented packet with weird payload size of %d", payload_length);
				state->ip_header_err++;
				retval.code = XDP_CODE_FILTER_TOT_LEN_DROP;
				retval.action = XDP_DROP;
				goto done;
			}

			if (send_packet_too_big(ctx, state, &retval) < 0) {
				goto done; // state is updated inside send_packet_too_big
			}

			state->ptb_window_budget--;
			state->ptb_sent_count++;
			retval.code = XDP_CODE_FILTER_PTB;
			retval.action = XDP_TX;
			goto done;
		}

		retval.code = XDP_CODE_FILTER_IP_FRAG_DROP;
		retval.action = XDP_DROP;
		goto done;
	}

	retval.code = XDP_CODE_MU;
	retval.action = XDP_PASS;

done:
	if (retval.action == XDP_PASS) {
		bpf_debug("xdp_filter: CALL_NEXT()");
		CALL_NEXT();
	}
	bpf_debug("xdp_filter: returning action %i, code %u", retval.action, retval.code);
	XDPCAP_RETURN(ctx, retval);
}

char _license[] SEC("license") = "APL";
