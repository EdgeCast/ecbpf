#ifndef _rules_h
#define _rules_h

#include <stdint.h>
#include <limits.h>
#include <linux/bpf.h>
#include "hash.h"
#include "libecbpf.h"
#define RULES_MAX 64
#define SHA1_SIZE 20

/*
 * Declarations
 */
struct fw_cfg;
struct rule;
struct test;
struct rule_map_fds; // internal to rules.h

// options
enum fw_opts_type; // Options header for each option
struct fw_opts; // Generic opts struct with common header of type and list pointers
struct fw_packet_opts;
struct fw_ip_opts;
struct fw_tcp_opts;
struct fw_udp_opts;
struct fw_icmp_opts;
struct fw_meta_opts;

// option components
struct fw_ip; // List of IP addresses
struct fw_port; // List of ports

/*
 * Configuration and rules
 */
struct fw_cfg {
	struct rule *rules[RULES_MAX];
	struct test *tests[UCHAR_MAX+1];
	int rules_count;
	int tests_count;
	char *filename;
};

struct rule {
	struct fw_opts *opts;
};

struct test {
	// sha1 of packet
	unsigned char sha1[SHA1_SIZE];
	// expected return from xdp
	enum xdp_action act;
	struct test *next;
};

/*
 * Options for various layers/protocols
 */
enum fw_opts_type {
	FW_OPT_PACKET,
	FW_OPT_IP,
	FW_OPT_TCP,
	FW_OPT_UDP,
	FW_OPT_ICMP,
	FW_OPT_TEST,
	FW_OPT_META
};


#define FW_OPT_HEADER \
	enum fw_opts_type opt_type;\
	struct fw_opts *next;\
	struct fw_opts *tail;\
	void (*free)(struct fw_opts *); \
	void (*print)(FILE *, struct fw_opts *); \
	void (*add)(struct rule_map_fds *, struct fw_opts *, int rule_num);

struct fw_opts {
	FW_OPT_HEADER
};

struct fw_packet_opts {
	FW_OPT_HEADER

	// options
	int length;
};

struct fw_ip_opts {
	FW_OPT_HEADER

	// options
	unsigned int family;
	int ttl;
	struct fw_ip* saddr;
	struct fw_ip* daddr;
};

struct fw_tcp_opts {
	FW_OPT_HEADER

	// options
	int window;
	struct fw_port* sport;
	uint8_t flag_set;
	uint8_t mask;
};

struct fw_udp_opts {
	FW_OPT_HEADER

	// options
	struct fw_port* sport;
};

struct fw_icmp_opts {
	FW_OPT_HEADER

	// options
	unsigned int family;
	int type; // icmp type
};

struct fw_meta_opts {
	FW_OPT_HEADER

	// options
	char *name;
	char *rule;
};

/*
 * Option Components
 */
struct fw_ip {
	unsigned int family;
	int any;
	int prefix_len;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
	struct fw_ip *tail;
	struct fw_ip *next;
};

struct fw_port {
	int start;
	int end;
	struct fw_port *next;
	struct fw_port *tail;
};

// Exported prototypes from rules.c
struct rule *rule_new(struct fw_opts *opts);
void rule_free(struct rule *rule);

// option free routines
void fw_packet_opts_free(struct fw_opts *opt);
void fw_ip_opts_free(struct fw_opts *opt);
void fw_tcp_opts_free(struct fw_opts *opt);
void fw_udp_opts_free(struct fw_opts *opt);
void fw_icmp_opts_free(struct fw_opts *opt);
void fw_meta_opts_free(struct fw_opts *opt);

// option print routines
void fw_packet_opts_print(FILE *fh, struct fw_opts *opts);
void fw_ip_opts_print(FILE *fh, struct fw_opts *opt);
void fw_tcp_opts_print(FILE *fh, struct fw_opts *opt);
void fw_udp_opts_print(FILE *fh, struct fw_opts *opt);
void fw_icmp_opts_print(FILE *fh, struct fw_opts *opt);
void fw_meta_opts_print(FILE *fh, struct fw_opts *opt);

// option add routines
void fw_packet_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);
void fw_ip_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);
void fw_tcp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);
void fw_udp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);
void fw_icmp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);
void fw_meta_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num);

int rules_add(struct ecbpf_ctx *ctx, struct fw_cfg *config);
int rules_validate(char *rules_filename);

void rule_print(FILE *fh, struct fw_opts *);
char *rule_to_str(struct fw_opts *);

#endif // _rules_h
