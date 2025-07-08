#ifndef _XDP_FILTER_H
#define _XDP_FILTER_H

#include <stdint.h>
#include <time.h>

#define XDP_PROG_ARRAY_IDX XDP_FILTER_IDX
#define XDP_FILTER_PROG_NAME xdp_filter_prog
#define XDP_FILTER_PROG_O "xdp_filter_kern.o"

#define XDP_FILTER_TRIE_MAX 8192
#define IPV4_MAX_PREFIXLEN 32
#define IPV6_MAX_PREFIXLEN 128

#define XDP_FILTER_NAME_LEN 64

#define XDP_FILTER_CONFIG_MAP xdp_filter_config_v1 // map name to change with versions
#define XDP_FILTER_STATE_MAP xdp_filter_state_v1 // map name to change with versions
#define XDP_FILTER_IP_MAP xdp_filter_ip_src_v1 // map name to change with versions
#define XDP_FILTER_IP6_MAP xdp_filter_ip6_src_v1 // map name to change with versions

#define CONFIG_NO_CHANGE -1
struct filter_configuration {
	bool frags_drop; // Ability to turn off dropping frags
	bool ptb_send; // Send a Packet Too Big response if we get a first frag
	int ptb_max_pps; // Rate limit the sending of PTB in pps
};

struct filter_state {
	// Statistics
	uint64_t eth_frame_err; // Ethernet header, ip header or ip6 header too short
	uint64_t ip_header_err; // iphl != 5 or evil bit
	uint64_t ip6_header_err; // unused
	uint64_t ip_drop_count; // Number of IPv4 packets dropped
	uint64_t ip_frag_drop_count; // Number of frags dropped
	uint64_t ptb_sent_count; // Number of ICMP PTB messages sent
	uint64_t ptb_err_count; // Failed to launch a PTB for some reason
	uint64_t ptb_mem_err_count; // Failed to adjust a PTB for some reason
	uint64_t ip6_drop_count; // Number of IPv6 packets dropped
	// Rate limit tracking
	uint64_t ptb_last_sent; // ktime of the last PTB sent
	int ptb_window_budget; // Remaining PTB allocation for this window
};

struct filter_drop_entry {
	char tag[XDP_FILTER_NAME_LEN];  // Tag is for the end user to help differentiate between blocks
	time_t load_time;
};

struct ip_trie_key {
	uint32_t prefix_len;
	union {
		uint32_t key;
		struct in_addr addr;
	};
};

struct ip6_trie_key {
	uint32_t prefix_len;
	union {
		uint8_t key[16];
		struct in6_addr addr6;
	};
};

#ifdef ECBPF_KERN // Definitions for BPF programs

#include <bpf_helpers.h>


struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct ip_trie_key));
	__uint(value_size, sizeof(struct filter_drop_entry));
	__uint(max_entries, XDP_FILTER_TRIE_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} XDP_FILTER_IP_MAP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct ip6_trie_key));
	__uint(value_size, sizeof(struct filter_drop_entry));
	__uint(max_entries, XDP_FILTER_TRIE_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} XDP_FILTER_IP6_MAP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct filter_configuration));
} XDP_FILTER_CONFIG_MAP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct filter_state));
} XDP_FILTER_STATE_MAP SEC(".maps");

#else // Userspace Definitions

#include <linux/if.h>
#include "libecbpf.h"

struct filter_interface {
	char name[IFNAMSIZ];
	struct ecbpf_ctx* ctx;
	struct filter_map_fds* fds;
};

#endif // end userland/kernel
#endif // _XDP_FILTER_H
