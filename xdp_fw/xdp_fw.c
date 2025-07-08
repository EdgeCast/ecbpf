/*
 * Loader for xdp_printk_kern.o.  This is intended to be a simple prototype subprogram loader.
 */

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
#include <json-c/json.h> // libjson-c-dev

#include "libecbpf.h"
#include "xdp_fw.h"
#include "rootmaps.h"
#include "cfg.h"
#include "rules.h"
#include "test.h"

#define IF_SEP ",-:" // Separators for interface list
#define FW_TEST_NAMESPACE "test"

static int mode_flag;
//static char rules_filename[PATH_MAX];
//static char test_pcap_filename[PATH_MAX];

void attach(struct interface *interface, char *program, struct fw_cfg *config);
void update(struct interface *interface, char* program, struct fw_cfg *config);
void detach(struct interface *interface);
void usage(int ret);

enum flags {
	FLAG_ATTACH,
	FLAG_DETACH,
	FLAG_UPDATE,
	FLAG_TEST,
	FLAG_VALIDATE,
	FLAG_STATS
};

void usage(int ret) {

	printf("xdp_fw: XDP firewall loader!\n\n"
		   "   --attach: Attach program\n"
		   "   --detach: Detach program\n"
		   "   --debug: Print debug messages\n"
		   "   --stats: Print firewall statistics\n"
		   "   --test <file>: Test using a pcap\n"
		   "   --test-log <file>: Log statistics from test\n"
		   "   --update: Update rules (program required if not in default location)\n"
		   "   --validate: Validate rules"
		   "   --rules <file>: Rules to load\n"
		   "   --interface <int> - Must have root array loaded.\n"
		   "   --program <xdp_fw_kern.o> - Full path to xdp_fw_kern.o\n");
	exit(ret);
}

void attach(struct interface *interface, char *program, struct fw_cfg *config) {

	int id;
	int err;

	/* check if a printk is already loaded */
	id = ecbpf__subprogram_slot_prog_id(interface->ctx, XDP_PROG_ARRAY_IDX);
	if (id >= 0) {
		errx(EX_USAGE, "Program already in slot on interface %s.", interface->ifname);
	}

	err = ecbpf__subprogram_open(interface->ctx, program);
	if (err) {
		errx(EX_SOFTWARE, "Failed to load subprogram from %s.", program);
	}

	err = ecbpf__subprogram_attach(interface->ctx, xstr(XDP_FW_PROG_NAME), XDP_PROG_ARRAY_IDX);
	if (err) {
		errx(EX_SOFTWARE, "Failed to attach subprogram to interface %s.", interface->ifname);
	}

	rules_add(interface->ctx, config);
}

// Initially, there was a revision map with an integer to track if 
// the rules had been updated while running and we would pass on the 
// packet if that were the case.  That resulted in two map lookups, one 
// at the start of processing a packet and one at the end.  By making updating
// dumb, we remove two problems.  One is a kernel/userland mismatch.  The other
// is fewer map lookups per packet.
void update(struct interface *interface, char* program, struct fw_cfg *config) {
	int id;
	int err;

	/* check if a printk is already loaded */
	id = ecbpf__subprogram_slot_prog_id(interface->ctx, XDP_PROG_ARRAY_IDX);
	if (id >= 0) {
		detach(interface);
	}

	attach(interface, program, config);
}



void detach(struct interface *interface) {
	int err;

	err = ecbpf__subprogram_detach(interface->ctx, XDP_PROG_ARRAY_IDX);

	if (err)
		errx(EX_SOFTWARE, "Failed to detach from root array for interface %s.", interface->ifname);
}

void print_stats(struct interface *interfaces) {
	struct xdp_fw_rule_meta meta;
	struct interface *interface = interfaces;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	uint64_t values[nr_cpus];
	uint64_t value;
	struct json_object *rootobj, *ifobj, *ruleobj;
	int xdp_fw_stats_fd, xdp_fw_rule_meta_fd;

	rootobj = json_object_new_object();

	while (interface) {
		xdp_fw_stats_fd = ecbpf__get_map_fd(interface->ctx, "xdp_fw_stats");
		xdp_fw_rule_meta_fd = ecbpf__get_map_fd(interface->ctx, "xdp_fw_rule_meta");

		if (xdp_fw_stats_fd < 0) {
			errx(EX_SOFTWARE, "Failed to get map fd for xdp_fw_stats for interface %s.", interface->ifname);
		}

		if (xdp_fw_rule_meta_fd < 0) {
			errx(EX_SOFTWARE, "Failed to get map fd for xdp_fw_rule_meta for interface %s.", interface->ifname);
		}


		ifobj = json_object_new_array();
		json_object_object_add(rootobj, interface->ifname, ifobj);

		for (uint32_t key = 0; key < XDP_RULE_NUM_MAX; key++) {
			if ((bpf_map_lookup_elem(xdp_fw_rule_meta_fd, &key, &meta)) != 0) {
				break; // end of rules
			}


			if ((bpf_map_lookup_elem(xdp_fw_stats_fd, &key, values)) != 0) {
				errx(EX_SOFTWARE, "Failed to lookup key %u", key);
			}
			value = 0;
			for (int i = 0 ; i < nr_cpus ; i++)
				value += values[i];

			ruleobj = json_object_new_object();

			json_object_object_add(ruleobj, "rule_number", json_object_new_int(key));
			/* The version of libjson-c that ships with Bionic does not
			 * include the json_object_new_uint64 function.  Since these
			 * are counters, we will mask the most significant bit for now.
			 */
			//json_object_object_add(ruleobj, "hits", json_object_new_int64(value & UINT64_MAX >> 1));
			json_object_object_add(ruleobj, "hits", json_object_new_int64(value));
			json_object_object_add(ruleobj, "name", json_object_new_string(meta.name));
			json_object_object_add(ruleobj, "rule", json_object_new_string(meta.rule));
			json_object_array_add(ifobj, ruleobj);
		}
		interface = interface->next;
	}

	printf("%s\n", json_object_to_json_string_ext(rootobj, JSON_C_TO_STRING_PRETTY));

	json_object_put(rootobj);
}

// If ifname is null, we create a special interface for test.c
struct interface* interface_new(char *ifname) {
	struct interface *newif;
	struct ecbpf_ctx *ctx;

	newif = calloc(1, sizeof(struct interface));
	if (ifname)
		newif->ifname = strdup(ifname);
	else
		newif->ifname = strdup(FW_TEST_NAMESPACE);

	/* 
	 * Setup the ecbpf context
	 */
	ctx = ecbpf_ctx__new();
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_stats");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_rule_meta");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_length_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip_ttl_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip_saddr_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip_daddr_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip6_saddr_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip6_daddr_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_ip_proto_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_tcp_sport_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_tcp_window_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_tcp_flags_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_udp_sport_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_icmp_type_rules");
	ecbpf_ctx__set_pinned_map(ctx, "xdp_fw_icmp6_type_rules");

	if (ifname)
		ecbpf_ctx__set_interface(ctx, ifname);
	else
		ecbpf_ctx__set_namespace(ctx, FW_TEST_NAMESPACE);

	if (ifname && ecbpf__check_root_program(ctx)) {
		errx(EX_CONFIG, "Root program array not attached to interface %s", ifname);
	}

	newif->ctx = ctx;

	return newif;
}

void interface_free(struct interface *interface) {
	ecbpf_ctx__free(interface->ctx);
	free(interface->ifname);
	free(interface);
}

int main(int argc, char **argv) {
	int err = 0;
	int map_fd;

	char name[256];
	char *rules_filename = NULL;
	char *test_pcap_filename = NULL;
	struct interface *interfaces = NULL;
	struct interface *cur, *newif;
	struct fw_cfg *config = NULL;
	char *program = NULL;
	char *test_log = NULL;
	char *ifname;
	char *port = NULL;
	int opt;
	int option_index = 0;

	struct perf_buffer_opts perf_buffer_opts = {};

	struct option options[] = {
		{ "attach", no_argument, &mode_flag, FLAG_ATTACH },
		{ "update", no_argument, &mode_flag, FLAG_UPDATE },
		{ "validate", no_argument, &mode_flag, FLAG_VALIDATE },
		{ "test", required_argument, 0, 't' },
		{ "rules", required_argument, 0, 'r' },
		{ "stats", no_argument, &mode_flag, FLAG_STATS },
		{ "detach", no_argument, &mode_flag, FLAG_DETACH },
		{ "debug", no_argument, &mode_flag, 'd'},
		{ "interface", required_argument, 0, 'i' },
		{ "program", required_argument, 0, 'P' },
		{ "test-log", required_argument, 0, 'L'},
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt =
		getopt_long(argc, argv, "di:P:t:r:hs", options,
				&option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'i':
			// Allow a dash separated list of interfaces to make systemd templates work...
			for (ifname = strtok(optarg, IF_SEP); ifname ; ifname = strtok(NULL, IF_SEP)) {
				for (struct interface *p = interfaces; p ; p = p->next) {
					if (strcmp(ifname, p->ifname) == 0)
						errx(EXIT_FAILURE, "Duplicate interface %s", ifname);
				}
				newif = interface_new(ifname);
				newif->next = interfaces;
				interfaces = newif;
			}
			break;
		case 'L':
			test_log = strdup(optarg);
			break;
		case 'P':
			program = strdup(optarg);
			break;
		case 'r':
			rules_filename = strdup(optarg);
			break;
		case 't':
			mode_flag = FLAG_TEST;
			test_pcap_filename = strdup(optarg);
			break;
		case 's':
			mode_flag = FLAG_STATS;
			break;
		case 'd':
			ecbpf_log_set_debug();
			break;
		default:
			usage(0);
			break;
		}
	}

	// fill in defaults
	if (program == NULL) {
		program = strdup(XDP_FW_PROG_O);
	}

	// Validate args
	if (interfaces == NULL && (mode_flag != FLAG_TEST && mode_flag != FLAG_VALIDATE)) {
		fprintf(stderr, "Interface must be supplied\n");
		err = EX_USAGE;
		goto done;
	}

	if ((mode_flag == FLAG_UPDATE || mode_flag == FLAG_VALIDATE || mode_flag == FLAG_ATTACH) &&
		rules_filename == NULL) {
		fprintf(stderr, "Rules filename not supplied via --rules\n");
		err = EX_USAGE;
		goto done;
	}

	switch (mode_flag) {
	case FLAG_ATTACH:
		config = cfg_new(rules_filename);
		cur = interfaces;
		while (cur) {
			attach(cur, program, config);
			cur = cur->next;
		}
		cfg_free(config);
		break;
	case FLAG_UPDATE:
		cur = interfaces;
		config = cfg_new(rules_filename);
		while (cur) {
			update(cur, program, config);
			cur = cur->next;
		}
		cfg_free(config);
		break;
	case FLAG_VALIDATE:
		rules_validate(rules_filename);
		break;
	case FLAG_TEST:
		// No multitest
		test(program, rules_filename, test_pcap_filename, test_log);
		break;
	case FLAG_DETACH:
		cur = interfaces;
		while (cur) {
			detach(cur);
			cur = cur->next;
		}
		break;
	case FLAG_STATS:
		print_stats(interfaces);
		break;
	}

done:
	while (interfaces) {
		cur = interfaces;
		interfaces = interfaces->next;
		interface_free(cur);
	}

	if (program)
		free(program);
	if (test_log)
		free(test_log);

	return err;
}
