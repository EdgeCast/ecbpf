#define ECBPF_KERN

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <stdint.h>
#include <strings.h>
#include <limits.h>

#include "xdp_fw.h"
#include "libecbpf_kern.h"

/*
 * Packet position management
 */
struct hdr_cursor {
	void *pos;
	void *data_start;
	void *data_end;
	uint16_t h_proto;
	xdp_fw_ruleset matches;
};

static __always_inline int invalid_position(struct hdr_cursor *cur) {
	return !(cur->pos < cur->data_end);
}

static __always_inline int setup_cursor(struct hdr_cursor *cur, struct xdp_md *ctx, xdpcap_retval_t *retval) {

	cur->data_start = (void *)(long)ctx->data;
	cur->pos = cur->data_start;
	cur->data_end = (void *)(long)ctx->data_end;
	cur->h_proto = 0;
	cur->matches = 0xffffffffffffffff;

	// This exists to make the verifier happy iirc
	if (invalid_position(cur)) {
		retval->action = XDP_ABORTED;
		retval->code = XDP_CODE_VERIFIER_ERR;
		return 1;
	}

	return 0;
}


/*
 * Ruleset lookup questions
 */
static __always_inline void fw_ruleset_ip_addr_q(struct hdr_cursor *cur, void *map, uint32_t addr) {
	void *valuep;
	xdp_fw_ruleset matches = 0;

	static struct fw_ip_trie_key key;

	key.prefix_len = 32;
	key.addr.s_addr = addr;

	valuep = bpf_map_lookup_elem(map, &key);
	if (valuep) {
		matches = *((xdp_fw_ruleset *) valuep);
		bpf_debug("fw_ruleset_ip_addr_q: addr: %x matches 0x%x", bpf_htonl(addr), matches);
	} else {
		bpf_debug("fw_ruleset_ip_addr_q: addr: %x matches <addr not in map>", bpf_htonl(addr));
	}

	cur->matches &= matches;
}

static __always_inline void fw_ruleset_ip6_addr_q(struct hdr_cursor *cur, void *map, struct in6_addr *addr) {
	void *valuep;
	xdp_fw_ruleset matches = 0;
	static struct fw_ip6_trie_key key;

	key.prefix_len = 128;
	key.addr6 = *addr;

	valuep = bpf_map_lookup_elem(map, &key);
	if (valuep) {
		matches = *((xdp_fw_ruleset *) valuep);
		// We can't pass more than 5 args because bpf (the macro hides a sizeof the format string)
		bpf_debug("fw_ruleset_ip6_addr_q: addr %x:...:%x matches 0x%x",
			bpf_htonl(addr->s6_addr32[0]),
			bpf_htonl(addr->s6_addr32[3]),
			matches);
	} else {
		// We can't pass more than 5 args because bpf (the macro hides a sizeof the format string)
		bpf_debug("fw_ruleset_ip6_addr_q: addr %x:...:%x matches <addr not in map>",
			bpf_htonl(addr->s6_addr32[0]),
			bpf_htonl(addr->s6_addr32[3]));
	}

	cur->matches &= matches;
}


static __always_inline void fw_ruleset_array_q(struct hdr_cursor *cur, void *map, uint32_t value) {
	void *valuep;
	xdp_fw_ruleset matches = 0;

	valuep = bpf_map_lookup_elem(map, &value);
	if (valuep) {
		matches = *((xdp_fw_ruleset *) valuep);
		bpf_debug("fw_ruleset_array_q: value 0x%x matches 0x%x", value, matches);
	} else {
		bpf_debug("fw_ruleset_array_q: value 0x%x matches <value not in map>", value);
	}

	cur->matches &= matches;
}

/*
 * Packet parsing
 */
static __always_inline int handle_tcp(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	// Use custom tcphdr that puts flags into a uint8_t
	struct tcphdr_flag_byte *tcph = cur->pos;

	if ((void *)(tcph + 1) > cur->data_end) {
		retval->code = XDP_CODE_TCP_LEN_ERR; 
		retval->action = XDP_ABORTED;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_tcp_window_rules, tcph->window);
	if (!cur->matches) {
		bpf_debug("handle_tcp: PASS for no WINDOW matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_tcp_flags_rules, tcph->flags);
	if (!cur->matches) {
		bpf_debug("handle_tcp: PASS for no FLAGS matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_tcp_sport_rules, tcph->source);
	if (!cur->matches) {
		bpf_debug("handle_tcp: PASS for no SOURCE PORT matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	return 0;
}

static __always_inline int handle_udp(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	struct udphdr *udph = cur->pos;

	if ((void *)(udph + 1) > cur->data_end) {
		retval->code = XDP_CODE_UDP_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_udp_sport_rules, udph->source);
	if (!cur->matches) {
		bpf_debug("handle_udp: PASS for no SOURCE PORT matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	return 0;
}

static __always_inline int handle_icmp(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	struct icmphdr *icmph = cur->pos;

	if ((void *)(icmph + 1) > cur->data_end) {
		retval->code = XDP_CODE_ICMP_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_icmp_type_rules, icmph->type);
	if (!cur->matches) {
		bpf_debug("handle_icmp: PASS for no TYPE matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	return 0;
}

static __always_inline int handle_icmp6(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	struct icmp6hdr *icmph = cur->pos;

	if ((void *)(icmph + 1) > cur->data_end) {
		retval->code = XDP_CODE_ICMP_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	fw_ruleset_array_q(cur, &xdp_fw_icmp6_type_rules, icmph->icmp6_type);
	if (!cur->matches) {
		bpf_debug("handle_icmp6: PASS for no TYPE matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	return 0;
}

static __always_inline int handle_ipv6hdr(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	struct ipv6hdr *ip6h = cur->pos;

	if ((void *)(ip6h + 1) > cur->data_end) {
		retval->code = XDP_CODE_IP6_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	/*
	 * Check proto
	 */
	fw_ruleset_array_q(cur, &xdp_fw_ip_proto_rules, ip6h->nexthdr);
	if (!cur->matches) {
		bpf_debug("handle_ipv6hdr: PASS for no IP_PROTO matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check for TTL rules
	 */
	fw_ruleset_array_q(cur, &xdp_fw_ip_ttl_rules, ip6h->hop_limit);
	if (!cur->matches) {
		bpf_debug("handle_ipv6hdr: PASS for no IP_TTL matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check destination address
	 */
	fw_ruleset_ip6_addr_q(cur, &xdp_fw_ip6_daddr_rules, &ip6h->daddr);
	if (!cur->matches) {
		bpf_debug("handle_ipv6hdr: PASS for no IP dest address matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check source address
	 */
	fw_ruleset_ip6_addr_q(cur, &xdp_fw_ip6_saddr_rules, &ip6h->saddr);
	if (!cur->matches) {
		bpf_debug("handle_ipv6hdr: PASS for no IP source address matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	cur->pos += sizeof(*ip6h);

	switch (ip6h->nexthdr) {
	case IPPROTO_TCP:
		return handle_tcp(cur, retval);
	case IPPROTO_UDP:
		return handle_udp(cur, retval);
	case IPPROTO_ICMPV6:
		return handle_icmp6(cur, retval);
	};

	bpf_debug("handle_ipv6hdr: PASS for unknown IPPROTO");
	retval->code = XDP_CODE_MU;
	retval->action = XDP_PASS;
	return 1;
}

static __always_inline int handle_iphdr(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	struct iphdr *iph = cur->pos;

	/*
	 * Check IP header length fits and some basic sanity
	 */
	if ((void *)(iph + 1) > cur->data_end) {
		retval->code = XDP_CODE_IP_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	// No header options expected (should be handled by the filter)
	if (iph->ihl != 5) {
		bpf_debug("handle_iphdr: PASS for IP options present");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	// Skip fragmented packets (should be handled by the filter)
	if (iph->frag_off & ~bpf_htons(IP_DF)) {
		bpf_debug("handle_iphdr: PASS for fragment");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check proto
	 */
	fw_ruleset_array_q(cur, &xdp_fw_ip_proto_rules, iph->protocol);
	if (!cur->matches) {
		bpf_debug("handle_iphdr: PASS for no IP_PROTO matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check for TTL rules
	 */
	fw_ruleset_array_q(cur, &xdp_fw_ip_ttl_rules, iph->ttl);
	if (!cur->matches) {
		bpf_debug("handle_iphdr: PASS for no IP_TTL matches %i", cur->matches);
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check destination address
	 */
	fw_ruleset_ip_addr_q(cur, &xdp_fw_ip_daddr_rules, iph->daddr);
	if (!cur->matches) {
		bpf_debug("handle_iphdr: PASS for no IP_DADDR matches %i", cur->matches);
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Check source address
	 */
	fw_ruleset_ip_addr_q(cur, &xdp_fw_ip_saddr_rules, iph->saddr);
	if (!cur->matches) {
		bpf_debug("handle_iphdr: PASS for no IP_SADDR matches %i", cur->matches);
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	cur->pos += sizeof(*iph);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		return handle_tcp(cur, retval);
	case IPPROTO_UDP:
		return handle_udp(cur, retval);
	case IPPROTO_ICMP:
		return handle_icmp(cur, retval);
	};

	bpf_debug("handle_iphdr: PASS for unknown IPPROTO");
	retval->code = XDP_CODE_MU;
	retval->action = XDP_PASS;
	return 1;
}

static __always_inline int handle_ethhdr(struct hdr_cursor *cur, xdpcap_retval_t *retval) {
	uint16_t eth_proto;
	struct ethhdr *eth = cur->pos;
	struct vlan_hdr *vlh;

	if ((void *)(eth + 1) > cur->data_end) {
		retval->code = XDP_CODE_ETH_LEN_ERR;
		retval->action = XDP_ABORTED;
		return 1;
	}

	cur->h_proto = bpf_ntohs(eth->h_proto);
	// Advance cursor
	cur->pos += sizeof(*eth);

	// Check for vlan header, we don't handle Q in Q...
	if (cur->h_proto == ETH_P_8021Q) {
		vlh = cur->pos;
		if ((void *)(vlh + 1) > cur->data_end) {
			retval->code = XDP_CODE_FW_NO_QINQ;
			retval->action = XDP_ABORTED;
			return 1;
		}
		cur->h_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
		cur->pos += sizeof(*vlh);
	}

	/*
	 * Check length
	 */
	uint16_t length = cur->data_end - cur->data_start;
	fw_ruleset_array_q(cur, &xdp_fw_length_rules, length);

	if (!cur->matches) {
		bpf_debug("handle_ethhdr: No packet length matches");
		retval->code = XDP_CODE_MU;
		retval->action = XDP_PASS;
		return 1;
	}

	/*
	 * Move onto IP layer
	 */
	switch (cur->h_proto) {
	case ETH_P_IP:
		return handle_iphdr(cur, retval);
	case ETH_P_IPV6:
		return handle_ipv6hdr(cur, retval);
	}

	bpf_debug("handle_ethhdr: Skipping non-ip packet");
	retval->code = XDP_CODE_MU;
	retval->action = XDP_PASS;
	return 1;
}

static uint32_t _ffs(xdp_fw_ruleset matches) {
	uint32_t i;
	if (matches == 0)
		return 0;

	for (i=0; !(matches & 1) && (i < XDP_RULE_NUM_MAX) ; i++)
		matches = matches >> 1;

	return i;
}

/* initially based off of linux/samples/bpf/xdp_sample_pkts_kern.c */
SEC("xdp")
int XDP_FW_PROG_NAME(struct xdp_md *ctx)
{
	struct hdr_cursor cur;
	xdpcap_retval_t retval = {XDP_PASS, XDP_CODE_MU, 0x00};
	uint32_t rule;
	uint64_t *count;
	uint64_t initial_count = 1;
	bpf_debug("-------- START PACKET --------");

	if(setup_cursor(&cur, ctx, &retval))
		goto done;

	if(handle_ethhdr(&cur, &retval))
		goto done;

	// We take the first matching rule for status update
	rule = _ffs(cur.matches);
	count = bpf_map_lookup_elem(&xdp_fw_stats, &rule);
	if (count)
		*count += 1;
	else
		bpf_map_update_elem(&xdp_fw_stats, &rule, &initial_count, BPF_ANY);

	bpf_debug("xdp_fw: All matches 0x%x Matching Rule: %i", cur.matches, rule);

	if (cur.matches) {
		retval.code = XDP_CODE_FW_DROP;
		retval.meta = cur.matches;
		retval.action = XDP_DROP;
		goto done;
	}

done:
	if (retval.action == XDP_PASS) {
		bpf_debug("xdp_fw: CALL_NEXT()");
		CALL_NEXT();
	}
	bpf_debug("xdp_fw: returning action %i code %u", retval.action, retval.code);
	XDPCAP_RETURN(ctx, retval);
}

char _license[] SEC("license") = "APL";
