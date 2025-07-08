/*
 * Routines for adding rules.  Entry point is add_rules()
 */
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <time.h>

#include "xdp_fw.h"
#include "rootmaps.h"
#include "rules.h"
#include "cfg.h"

/*
 * Rule struct functions
 */
void fw_port_free(struct fw_port *port);
void fw_ip_free(struct fw_ip *ip);

struct rule *rule_new(struct fw_opts *opts) {
	struct rule *rule = calloc(1, sizeof(struct rule));

	rule->opts = opts;

	return rule;
}

#define CAST_O_TO_OPT(stype, type) \
	assert(o->opt_type == type); \
	struct stype *opt = (struct stype *) o;

void fw_packet_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_packet_opts, FW_OPT_PACKET);

	free(opt);
}

void fw_ip_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_ip_opts, FW_OPT_IP);

	if (opt->daddr)
		fw_ip_free(opt->daddr);
	if (opt->saddr)
		fw_ip_free(opt->saddr);
	free(opt);
}

void fw_tcp_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_tcp_opts, FW_OPT_TCP);

	fw_port_free(opt->sport);
	free(opt);
}

void fw_udp_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_udp_opts, FW_OPT_UDP);

	fw_port_free(opt->sport);
	free(opt);
}

void fw_icmp_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_icmp_opts, FW_OPT_ICMP);

	free(opt);
}

void fw_meta_opts_free(struct fw_opts *o) {
	CAST_O_TO_OPT(fw_meta_opts, FW_OPT_META);

	if (opt->name)
		free(opt->name);
	if (opt->rule)
		free(opt->rule);
	free(opt);
}

void rule_free(struct rule *rule) {
	struct fw_opts *opt, *next;

	opt = rule->opts;

	while(opt) {
		next = opt->next;
		opt->free(opt);
		opt = next;
	}

	free(rule);
}

void fw_port_free(struct fw_port *port) {
	struct fw_port *next;

	while (port != NULL) {
		next = port->next;
		free(port);
		port = next;
	}
}

void fw_ip_free(struct fw_ip *ip) {
	struct fw_ip *next;

	while (ip != NULL) {
		next = ip->next;
		free(ip);
		ip = next;
	}
}

/*
 * Map Handling Functions
 */
struct rule_map_fds {
	int xdp_fw_rule_meta_fd;
	int xdp_fw_length_rules_fd;
	int xdp_fw_ip_ttl_rules_fd;
	int xdp_fw_ip_saddr_rules_fd;
	int xdp_fw_ip_daddr_rules_fd;
	int xdp_fw_ip6_saddr_rules_fd;
	int xdp_fw_ip6_daddr_rules_fd;
	int xdp_fw_ip_proto_rules_fd;
	int xdp_fw_tcp_sport_rules_fd;
	int xdp_fw_tcp_window_rules_fd;
	int xdp_fw_tcp_flags_rules_fd;
	int xdp_fw_udp_sport_rules_fd;
	int xdp_fw_icmp_type_rules_fd;
	int xdp_fw_icmp6_type_rules_fd;
};

// Macro only intended to be used by rule_map_init_fds
#define _INIT_MAP_FD(name) \
		  rmfds->name ## _fd = ecbpf__get_map_fd(ctx, #name); \
		  if (rmfds->name ## _fd < 0) { \
			  errx(EX_SOFTWARE, "Failed to get map fd for " #name); \
		  }

// Populate a struct of file descriptors so we can easily break apart the rule
// adding into functions.
int rule_map_init_fds(struct ecbpf_ctx *ctx, struct rule_map_fds *rmfds) {
	_INIT_MAP_FD(xdp_fw_rule_meta)
	_INIT_MAP_FD(xdp_fw_length_rules)
	_INIT_MAP_FD(xdp_fw_ip_ttl_rules)
	_INIT_MAP_FD(xdp_fw_ip_saddr_rules)
	_INIT_MAP_FD(xdp_fw_ip_daddr_rules)
	_INIT_MAP_FD(xdp_fw_ip6_saddr_rules)
	_INIT_MAP_FD(xdp_fw_ip6_daddr_rules)
	_INIT_MAP_FD(xdp_fw_ip_proto_rules)
	_INIT_MAP_FD(xdp_fw_tcp_sport_rules)
	_INIT_MAP_FD(xdp_fw_tcp_window_rules)
	_INIT_MAP_FD(xdp_fw_tcp_flags_rules)
	_INIT_MAP_FD(xdp_fw_udp_sport_rules)
	_INIT_MAP_FD(xdp_fw_icmp_type_rules)
	_INIT_MAP_FD(xdp_fw_icmp6_type_rules)

	return 0;
}

// No longer used since we remove/reinsert the firewall to prevent version mismatch
int rule_map_clear(int map_fd) {
	int err = 0;
	struct bpf_map_info info = {};
	uint32_t len = sizeof(info);
	void *prev_key = NULL, *key;

	err = bpf_obj_get_info_by_fd(map_fd, &info, &len);
	if (err) {
		fprintf(stderr, "Failed to get map info\n");
		return err;
	}

	key = malloc(info.key_size);

	while (true) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
			} else {
				fprintf(stderr, "Failed to bpf_map_get_next_key\n");
			}
			break;
		}

		err = bpf_map_delete_elem(map_fd, key);
		if (err) {
			fprintf(stderr, "Failed to delete key\n");
			break;
		}
		prev_key = key;
	}

	free(key);

	return err;
}

int rule_map_array_set_bit(int map_fd, int rule_num, uint32_t value) {
	int err = 0;
	xdp_fw_ruleset rules;

	if ((bpf_map_lookup_elem(map_fd, &value, &rules)) != 0) {
		rules = 0; // first rule
	}

	rules |= 1 << rule_num;
	err = bpf_map_update_elem(map_fd, &value, &rules, BPF_ANY);

	return err;
}

int rule_map_lpm_trie_set_bit(int map_fd, int rule_num, void *key) {
	int err = 0;
	xdp_fw_ruleset rules;

	if ((bpf_map_lookup_elem(map_fd, key, &rules)) != 0) {
		rules = 0; // first rule
	}

	rules |= 1 << rule_num;
	err = bpf_map_update_elem(map_fd, key, &rules, BPF_ANY);

	return err;
}

/*
 * Rule handling function helpers
 */

// Handle adding IP addresses.  Since we only view one side of the connection, we 
// can use the same trie for saddr and daddr.
int fw_ip_add(struct fw_ip *fw_ip, int xdp_fw_ip_daddr_rules_fd,
			  int xdp_fw_ip6_daddr_rules_fd, int rule_num) {
	int err;
	struct fw_ip_trie_key key;
	struct fw_ip6_trie_key key6;

	switch (fw_ip->family) {
		case AF_INET:
			if (fw_ip->any) {
				// This is belt+suspenders, since they should be zero upon allocation
				fw_ip->prefix_len = 0;
				fw_ip->addr.s_addr = 0;
			}

			key.prefix_len = fw_ip->prefix_len;
			key.addr = fw_ip->addr;

			err = rule_map_lpm_trie_set_bit(xdp_fw_ip_daddr_rules_fd,
								 rule_num,
								 &key);

			if (err) {
				errx(EX_SOFTWARE, "Failed update in xdp_fw_ip_daddr_rules map.");
			}
			break;

		case AF_INET6:
			if (fw_ip->any) {
				fw_ip->prefix_len = 0;
				memset(&(fw_ip->addr6), 0, sizeof(struct in6_addr));
			}

			key6.prefix_len = fw_ip->prefix_len;
			key6.addr6 = fw_ip->addr6;

			err = rule_map_lpm_trie_set_bit(xdp_fw_ip6_daddr_rules_fd,
								 rule_num,
								 &key6);
			if (err) {
				errx(EX_SOFTWARE, "Failed update in xdp_fw_ip6_daddr_rules map.");
			}
			break;
	}
	return 0;
}

int fw_port_add(struct fw_port *fw_port, int xdp_port_map_fd, int rule_num) {
	struct fw_port *cur = fw_port;
	int err;

	while (cur != NULL) {

		if (cur->start > 65535 || cur->end > 65535)
			errx(EX_SOFTWARE, "Rule %i: Invalid port value too high: %i/%i", rule_num, cur->start, cur->end);
		if (cur->start < 1 || cur->end < 1)
			errx(EX_SOFTWARE, "Rule %i: Invalid port value too low: %i/%i", rule_num, cur->start, cur->end);

		for (int port = cur->start ; port < (cur->end + 1) ; port++) {
			err = rule_map_array_set_bit(xdp_port_map_fd, rule_num, htons(port));
			if (err) {
				errx(EX_SOFTWARE, "Failed update in port rules map.");
			}
		}

		cur = cur->next;
	}

	return 0;
}

/*
 * Rule handling functions
 */
void fw_meta_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_meta_opts, FW_OPT_META);
	
	int err;

	struct xdp_fw_rule_meta meta;

	strncpy(meta.name, opt->name, XDP_RULE_NAME_MAX - 1);
	strncpy(meta.rule, opt->rule, XDP_RULE_STR_MAX - 1);

	err = bpf_map_update_elem(rmfds->xdp_fw_rule_meta_fd, &rule_num, &meta, BPF_ANY);

	if (err)
		errx(EX_SOFTWARE, "Failed to add rule metadata for rule %i.", rule_num);
}

void fw_packet_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_packet_opts, FW_OPT_PACKET);

	int err;

	if (opt->length < 0) {
		// Wildcard rule
		uint16_t length = 0;
		do {
			err = rule_map_array_set_bit(rmfds->xdp_fw_length_rules_fd,
						 rule_num,
						 length);
			if (err) {
				errx(EX_SOFTWARE, "Failed update in xdp_fw_length_rules map.");
			}
			length++;
		} while (length != 0);
		return;
	}

	err = rule_map_array_set_bit(rmfds->xdp_fw_length_rules_fd,
			 	rule_num,
				opt->length);
}

void fw_ip_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_ip_opts, FW_OPT_IP);

	int err;
	// common to v6 and v4
	if (opt->ttl < 0) {
		// Wildcard
		uint8_t ttl = 0; //technically we shouldn't get length 0 from the router
		do {
			err = rule_map_array_set_bit(rmfds->xdp_fw_ip_ttl_rules_fd,
						rule_num,
						ttl);
			if (err) {
				errx(EX_SOFTWARE, "Failed update in xdp_fw_ip_ttl_rules map.");
			}

			ttl++;
		} while (ttl != 0);
	} else {
		err = rule_map_array_set_bit(rmfds->xdp_fw_ip_ttl_rules_fd,
					rule_num,
					opt->ttl);
		if (err) {
			errx(EX_SOFTWARE, "Failed update in xdp_fw_ip_ttl_rules map.");
		}
	}

	// Since src != dst, we reuse the daddr map
	struct fw_ip *addr = opt->saddr;
	while (addr != NULL) {
		fw_ip_add(addr,
			 rmfds->xdp_fw_ip_saddr_rules_fd,
			 rmfds->xdp_fw_ip6_saddr_rules_fd,
			 rule_num);
		addr = addr->next;
	}

	addr = opt->daddr;
	while (addr != NULL) {
		fw_ip_add(addr,
			 rmfds->xdp_fw_ip_daddr_rules_fd,
			 rmfds->xdp_fw_ip6_daddr_rules_fd,
			 rule_num);
		addr = addr->next;
	}
}

void fw_tcp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_tcp_opts, FW_OPT_TCP);

	int err;

	if (rule_map_array_set_bit(rmfds->xdp_fw_ip_proto_rules_fd, rule_num, IPPROTO_TCP))
		errx(EX_SOFTWARE, "Failed to update xdp_fw_ip_proto_rules_fd");

	if (opt->window < 0) {
		// Wildcard
		uint16_t window = 0;

		do {
			err = rule_map_array_set_bit(rmfds->xdp_fw_tcp_window_rules_fd, rule_num, window);
			if (err) {
				errx(EX_SOFTWARE, "Failed update in xdp_fw_tcp_window_rules map.");
			}
			window++;
		} while (window!=0);
	} else {
		err = rule_map_array_set_bit(rmfds->xdp_fw_tcp_window_rules_fd, rule_num, htons(opt->window));
		if (err) {
			errx(EX_SOFTWARE, "Failed update in xdp_fw_tcp_window_rules map.");
		}
	}

	fw_port_add(opt->sport,
			rmfds->xdp_fw_tcp_sport_rules_fd,
			rule_num);

	uint8_t flags = opt->flag_set;
	uint8_t mask = opt->mask;
	if (flags == 0) {
		// Wildcard
		for (uint8_t f = 1; f != 0 ; f++) {
			err = rule_map_array_set_bit(rmfds->xdp_fw_tcp_flags_rules_fd, rule_num, f);
			if (err) {
				errx(EX_SOFTWARE, "Failed to update xdp_fw_tcp_flags_rules map.");
			}
		}
	} else {
		// Loop through all possible flag combinations.  If the masked version is the
		// same as flags, add the unmasked value to the map.  This way we don't have to
		// worry about masking in the kernel.
		for (uint8_t f = 1; f != 0 ; f++) {
			if ( (f & mask) == flags ) {
				err = rule_map_array_set_bit(rmfds->xdp_fw_tcp_flags_rules_fd, rule_num, f);
				if (err) {
					errx(EX_SOFTWARE, "Failed to update xdp_fw_tcp_flags_rules map.");
				}
			}
		}
	}
}

void fw_udp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_udp_opts, FW_OPT_UDP);

	int err;

	if (rule_map_array_set_bit(rmfds->xdp_fw_ip_proto_rules_fd, rule_num, IPPROTO_UDP))
		errx(EX_SOFTWARE, "Failed to update xdp_fw_ip_proto_rules_fd");

	fw_port_add(opt->sport,
			rmfds->xdp_fw_udp_sport_rules_fd,
			rule_num);
}

void fw_icmp_opts_add(struct rule_map_fds *rmfds, struct fw_opts *o, int rule_num) {
	CAST_O_TO_OPT(fw_icmp_opts, FW_OPT_ICMP);
	int err;

	int icmp_proto, icmp_map_fd, icmp_wildcard;
	char *mapname;

	// Figure out which map to update based on protocol
	if (opt->family == AF_INET) {
		icmp_proto = IPPROTO_ICMP;
		icmp_map_fd = rmfds->xdp_fw_icmp_type_rules_fd;
		mapname = "xdp_fw_icmp_type_rules_fd";
	} else {
		icmp_proto = IPPROTO_ICMPV6;
		icmp_map_fd = rmfds->xdp_fw_icmp6_type_rules_fd;
		mapname = "xdp_fw_icmp6_type_rules_fd";
	}

	if (rule_map_array_set_bit(rmfds->xdp_fw_ip_proto_rules_fd, rule_num, icmp_proto))
		errx(EX_SOFTWARE, "Failed to update xdp_fw_ip_proto_rules_fd");

	if (opt->type < 0) {
		// Wildcard
		uint8_t type = 0;

		do {
			err = rule_map_array_set_bit(icmp_map_fd,
					    rule_num,
					    type);
			if (err) {
				errx(EX_SOFTWARE, "Failed update in %s map.", mapname);
			}
			type++;
		} while (type != 0);
	} else {
		err = rule_map_array_set_bit(icmp_map_fd,
				    rule_num,
				    opt->type);
		if (err) {
			errx(EX_SOFTWARE, "Failed update in %s map.", mapname);
		}
	}
}

int rules_add(struct ecbpf_ctx *ctx, struct fw_cfg *config) {
	struct rule_map_fds *rmfds = calloc(1, sizeof(struct rule_map_fds));
	struct rule *rule;
	struct fw_opts *cur;
	xdp_fw_ruleset rules = 0;

	// Populate the map file descriptors
	rule_map_init_fds(ctx, rmfds);

	// Loop thorough and add in rules
	for (int rule_num = 0; rule_num < config->rules_count; rule_num++) {
		rule = config->rules[rule_num];

		cur = rule->opts;

		while (cur) {
			cur->add(rmfds, cur, rule_num);
			cur = cur->next;
		}
	}

	free(rmfds);
	return 0;
}

int rules_validate(char *rules_filename) {
	struct fw_cfg *config = NULL;

	if (!rules_filename)
		errx(EX_USAGE, "Rules filename is null");

	printf("Validating rules file %s\n", rules_filename);
	config = cfg_new(rules_filename);

	cfg_print(config);

	cfg_free(config);

	printf("Well, if we made it this far, the rules are probably OK.\n");
	printf("---- End Rules Validation ---\n");
	return 0;
}

/*
 * Rule printing functions
 */
void print_wildcard(FILE *fh, int num) {
	if (num < 0)
		fprintf(fh, "any");
	else
		fprintf(fh, "%i", num); 
}

void fw_packet_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_packet_opts, FW_OPT_PACKET);

	fprintf(fh, "packet length ");
	print_wildcard(fh, opt->length); 
}

void fw_ip_print(FILE *fh, struct fw_ip *ip) {
	struct fw_ip *cur = ip;
        char ip_str[INET6_ADDRSTRLEN];

	fprintf(fh, "{ ");
	while (cur != NULL) {
		if (cur->any) {
			fprintf(fh, "any");
		} else {
			switch (cur->family) {
				case AF_INET:
					inet_ntop(cur->family, &(cur->addr), ip_str, sizeof(ip_str));
					break;
				case AF_INET6:
					inet_ntop(cur->family, &(cur->addr6), ip_str, sizeof(ip_str));
					break;
				default:
					fprintf(fh, "Unknown family");
					exit(1);
					break;
			}
			fprintf(fh, "%s/%i", ip_str, cur->prefix_len);
		}

		cur = cur->next;
		if (cur != NULL)
			fprintf(fh, ", ");
	}

	fprintf(fh, " }");
}

void fw_ip_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_ip_opts, FW_OPT_IP);

	fprintf(fh, "ip%s from ", opt->family == AF_INET6 ? "6" : "");
	fw_ip_print(fh, opt->saddr);
	fprintf(fh, " to ");
	fw_ip_print(fh, opt->daddr);
	fprintf(fh, " ttl ");
	print_wildcard(fh, opt->ttl); 
}

void fw_port_print(FILE *fh, struct fw_port *port) {
	struct fw_port *cur = port;

	fprintf(fh, "{ ");
	while (cur != NULL) {
		if (cur->start != cur->end)
			fprintf(fh, "%i-%i", cur->start, cur->end);
		else
			fprintf(fh, "%i", cur->start);

		cur = cur->next;
		if (cur != NULL)
			fprintf(fh, ", ");
	}

	fprintf(fh, " }");
}

void fw_tcp_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_tcp_opts, FW_OPT_TCP);

	fprintf(fh, "tcp window ");
	print_wildcard(fh, opt->window); 

	fprintf(fh, " sport ");
	fw_port_print(fh, opt->sport);
	fprintf(fh, " flags %02x mask %02x", opt->flag_set, opt->mask);
}

void fw_udp_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_udp_opts, FW_OPT_UDP);

	fprintf(fh, "udp sport ");
	fw_port_print(fh, opt->sport);
}

void fw_icmp_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_icmp_opts, FW_OPT_ICMP);

	if (opt->family == AF_INET)
		fprintf(fh, "icmp type ");
	else
		fprintf(fh, "icmp6 type ");

	print_wildcard(fh, opt->type); 
}

void fw_meta_opts_print(FILE *fh, struct fw_opts *o) {
	CAST_O_TO_OPT(fw_meta_opts, FW_OPT_META);

	fprintf(fh, "name \"%s\"", opt->name);
}

void rule_print(FILE *fh, struct fw_opts *opts) {
	bool space = false;

	struct fw_opts *cur = opts;

	while (cur) {
		if (space)
			fprintf(fh, " ");
		cur->print(fh, cur);
		space = true;
		cur = cur->next;
	}
}

char *rule_to_str(struct fw_opts *opts) {
	char *str;
	size_t size;
	FILE *fh;

	fh = open_memstream(&str, &size);

	if (!fh) {
		err(EX_SOFTWARE, "Failed to open memstream for rule printing");
	}

	rule_print(fh, opts);

	fclose(fh);

	return str;
}
