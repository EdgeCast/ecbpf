#ifndef _XDP_FW_H
#define _XDP_FW_H 1

#include <stdint.h>
#include <linux/types.h>

#define XDP_PROG_ARRAY_IDX XDP_FW_IDX
#define XDP_FW_PROG_NAME xdp_fw_prog
#define XDP_FW_PROG_O "xdp_fw_kern.o"
#define XDP_FW_VERS 1 // An integer for kernel vs userland
#define XDP_RULE_NAME_MAX 256
#define XDP_RULE_STR_MAX 4096
#define XDP_RULE_NUM_MAX 64
#define MAX_CPUS 128

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef uint64_t xdp_fw_ruleset;

// Special TCP header with flags as u8 for flag comparison
struct tcphdr_flag_byte {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u8	res1:4,
		doff:4;
	__u8	flags;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

// For storing metadata about rules in a map
struct xdp_fw_rule_meta {
	char name[XDP_RULE_NAME_MAX];
	char rule[XDP_RULE_STR_MAX];
};

// consistent with xdp_filter
struct fw_ip_trie_key {
	uint32_t prefix_len;
	union {
		uint32_t key;
		struct in_addr addr;
	};
};

struct fw_ip6_trie_key {
	uint32_t prefix_len;
	union {
		uint8_t key[16];
		struct in6_addr addr6;
	};
};


#ifdef ECBPF_KERN // Definitions for BPF programs

#include <bpf_helpers.h> // __uint and __type macros

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_RULE_NUM_MAX);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
} xdp_fw_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_RULE_NUM_MAX);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct xdp_fw_rule_meta));
} xdp_fw_rule_meta SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 65536);
} xdp_fw_length_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct fw_ip_trie_key));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, sizeof(xdp_fw_ruleset) * 8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_fw_ip_saddr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct fw_ip_trie_key));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, sizeof(xdp_fw_ruleset) * 8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_fw_ip_daddr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct fw_ip6_trie_key));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, sizeof(xdp_fw_ruleset) * 8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_fw_ip6_saddr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct fw_ip6_trie_key));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, sizeof(xdp_fw_ruleset) * 8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_fw_ip6_daddr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 256);
} xdp_fw_ip_ttl_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 256);
} xdp_fw_ip_proto_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 65536);
} xdp_fw_tcp_window_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 256);
} xdp_fw_tcp_flags_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 65536);
} xdp_fw_tcp_sport_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 65536);
} xdp_fw_udp_sport_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 256);
} xdp_fw_icmp_type_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(xdp_fw_ruleset));
	__uint(max_entries, 256);
} xdp_fw_icmp6_type_rules SEC(".maps");

#else // Userspace Definitions

#include "libecbpf.h"
struct interface {
	char *ifname;
	struct ecbpf_ctx *ctx;
	struct interface *next;
};

// Functions exported for test.c
void print_stats(struct interface *);
struct interface* interface_new(char *ifname);

#endif // ECBF_KERN

#endif // _XDP_FW_H
