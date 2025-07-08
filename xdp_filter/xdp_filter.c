#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#include <json-c/json.h> // libjson-c-dev

#include "libecbpf.h"
#include "xdp_filter.h"
#include "maps.h"
#include "stats.h"
#include "ip_chain.h"
#include "config.h"
#include "rootmaps.h"

#define IF_MAX 8 // Max number of interfaces for command line utilities, somewhat arbitrary
#define IF_SEP ",-:" // Separators for interface list

volatile sig_atomic_t exit_flag = false;
static int mode_flag;

enum flags {
	NO_FLAG,
	ATTACH_FLAG,
	DETACH_FLAG,
	STATUS_FLAG,
	CLEAR_STATUS_FLAG,
	CLEAR_IP_FLAG,
	DROP_IP_FLAG,
	UNDROP_IP_FLAG
};

/*
 * Internal Prototypes
 */
void status_statsd_sig_handler(int signo);
void status_statsd(struct filter_interface *interfaces, int interface_count, char* statsd_host, char* statsd_port);
void status_json(struct filter_interface *interfaces, int interface_count);
void status(struct filter_interface *interfaces, int interface_count);
int filter_new_ecbpf_ctx(struct filter_interface *interface);
int attach(struct filter_interface *interface, char *program);
int detach(struct filter_interface *interface, bool quiet);
void usage(int ret);

/*
 * Status functions
 */
void status_statsd_sig_handler(int signo) {
	exit_flag = true;
}

void status_statsd(struct filter_interface *interfaces, int interface_count, char* statsd_host, char* statsd_port) {
	struct sigaction sig_act;

	/* Setup signal handler */
	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;
	sig_act.sa_handler = status_statsd_sig_handler;
	sigaction(SIGTERM, &sig_act, NULL);
	sigaction(SIGINT, &sig_act, NULL);

	struct stats_statsd_ctx *ctx;

	ctx = stats_statsd_ctx_new(statsd_host, statsd_port);

	// Send stats loop
	while (!exit_flag) {
		for (int i = 0; i < interface_count; i++) {
			stats_statsd(ctx, &interfaces[i]);
		}
		sleep(1);
	}

	stats_statsd_ctx_free(ctx);
}

void status_json(struct filter_interface *interfaces, int interface_count) {
	struct json_object *root_obj;
	struct json_object *interface_obj;
	root_obj = json_object_new_object();

	// Maintain backwards compatibility
	if (interface_count == 1) {
		config_json(&interfaces[0], root_obj);
		stats_json(&interfaces[0], root_obj);
		maps_json(&interfaces[0], root_obj);
	} else {
		for (int i = 0; i < interface_count; i++) {
			interface_obj = json_object_new_object();
			json_object_object_add(root_obj, interfaces[i].name, interface_obj);
			config_json(&interfaces[i], interface_obj);
			stats_json(&interfaces[i], interface_obj);
			maps_json(&interfaces[i], interface_obj);
		}
	}

	printf("%s\n", json_object_to_json_string_ext(root_obj, JSON_C_TO_STRING_PRETTY));
	json_object_put(root_obj);
}

void status(struct filter_interface *interfaces, int interface_count) {
	for (int i = 0; i < interface_count; i++) {
		printf("=================== Status for interface '%s' ===================\n", interfaces[i].name);
		config_print(&interfaces[i]);
		maps_print(&interfaces[i]);
		stats_print(&interfaces[i]);
	}
}

/*
 * XDP Attach/Detach functions
 */
int filter_new_ecbpf_ctx(struct filter_interface *interface) {
	int err = 0;
	struct ecbpf_ctx *ctx;

	/* Setup the ecbpf context */
	ctx = ecbpf_ctx__new();
	ecbpf_ctx__set_pinned_map(ctx, xstr(XDP_FILTER_CONFIG_MAP));
	ecbpf_ctx__set_pinned_map(ctx, xstr(XDP_FILTER_STATE_MAP));
	ecbpf_ctx__set_pinned_map(ctx, xstr(XDP_FILTER_IP_MAP));
	ecbpf_ctx__set_pinned_map(ctx, xstr(XDP_FILTER_IP6_MAP));

	err = ecbpf_ctx__set_interface(ctx, interface->name);

	if (err != 0) {
		fprintf(stderr, "Failed to  ecbpf_ctx__set_interface interface '%s'\n", interface->name);
		ecbpf_ctx__free(ctx);
		goto done;
	}

	/* Make sure interface has a root array */
	if (ecbpf__check_root_program(ctx)) {
		fprintf(stderr, "Root program array not attached to interface %s\n", interface->name);
		ecbpf_ctx__free(ctx);
		err = 1;
		goto done;
	}

	interface->ctx = ctx;

done:
	return err;
}

/* Returns 0 on success.  Some failures considered fatal. */
int attach(struct filter_interface *interface, char *program) {
	int id;
	int err = 0;

	/* check if xdp filter is already loaded */
	id = ecbpf__subprogram_slot_prog_id(interface->ctx, XDP_PROG_ARRAY_IDX);
	if (id >= 0) {
		fprintf(stderr, "Program already in slot on interface '%s'\n", interface->name);
		err = 1;
		goto done;
	}

	err = ecbpf__subprogram_open(interface->ctx, program);
	if (err) {
		fprintf(stderr, "Failed to load subprogram from %s\n", program);
		goto done;
	}

	err = ecbpf__subprogram_attach(interface->ctx, xstr(XDP_FILTER_PROG_NAME), XDP_PROG_ARRAY_IDX);
	if (err) {
		fprintf(stderr, "Failed to attach subprogram for interface '%s'.\n", interface->name);
		err = 1;
		goto done;
	}

	/* Now do the configuration */
	err = config_init(interface);
	if (err) {
		fprintf(stderr, "Failed to set initial configuration for interface '%s'.\n", interface->name);
		detach(interface, false);
		goto done;
	}

done:
	return err;
}

/* Returns 0 on success.  Some failures considered fatal. */
int detach(struct filter_interface *interface, bool quiet) {
	int err;

	err = ecbpf__subprogram_detach(interface->ctx, XDP_PROG_ARRAY_IDX);

	if (err) {
		if (!quiet)
			fprintf(stderr, "Failed to detach from root array on interface '%s'", interface->name);
		goto done;
	}

done:
	return err;
}

/*
 * Usage/Main functions
 */
void usage(int ret) {
	printf("xdp_filter\n\n"
		"   --attach - Attach program\n"
		"   --detach - Detach program\n"
		"   --status - print status and stats\n"
		"   --json - print output in json (currently applies to --status)\n"
		"   --interface <int>,<int2> - Must have root array loaded.\n"
		"   --drop - Drop traffic from the list of source ips specified using --ips.\n"
		"   --no-drop - Remove the list of IPs specified using --ips from the drop list.\n"
		"   --clear - Clear list of source IPs to drop traffic from.\n"
		"   --clear-status - Clear global stats.\n"
		"   --statsd - Start logging to statsd (can be combined with --attach).\n"
		"   --statsd-host - Defaults to localhost.\n"
		"   --statsd-port - Start logging to statsd.\n"
		"   --statsd-detach-on-exit - Detach on exit (for running from systemd).\n"
		"   --ips <ip/prefix_len>,... - List of IPs to act on (with --drop or --no-drop).\n"
		"   --tags 'IP one is X,IP two is Y,...' - Name tag for each ip to help the end user.\n"
		"   --program <xdp_filter_kern.o> - Full path to xdp_filter_kern.o\n"
		"   --frags-drop - Drop fragments\n"
		"   --ptb-max-pps - Max rate to send PTB per CPU. 0 to turn off.\n"
		"   --no-frags-drop - Don't drop fragments\n");
	exit(ret);
}

int main(int argc, char **argv) {
	int err = 0;

	struct filter_interface interfaces[IF_MAX];
	int interface_count = 0;
	struct ip_chain *chain = NULL;
	struct ip_chain *chain_idx = NULL;
	bool json = false;
	bool statsd_enable = false;
	bool statsd_detach_on_exit = false;
	char *program = NULL;
	char *port = NULL;
	char *tok;
	char *tag_list = NULL;
	char *iface = NULL;
	char statsd_host[254]; // https://devblogs.microsoft.com/oldnewthing/?p=7873
	char statsd_port[16]; // https://tools.ietf.org/html/rfc6335#section-5.1

	int opt;
	int option_index = 0;
	struct perf_buffer_opts perf_buffer_opts = {};

	// Configuration items.
	int ptb_max_pps = CONFIG_NO_CHANGE;
	int frags_drop = CONFIG_NO_CHANGE;
	strncpy(statsd_host, LIBECBPF_STATSD_HOST, sizeof(statsd_host)-1);
	strncpy(statsd_port, LIBECBPF_STATSD_PORT, sizeof(statsd_port)-1);

	struct option options[] = {
		{ "attach", no_argument, &mode_flag, ATTACH_FLAG },
		{ "detach", no_argument, &mode_flag, DETACH_FLAG },
		{ "status", no_argument, &mode_flag, STATUS_FLAG },
		{ "clear-status", no_argument, &mode_flag, CLEAR_STATUS_FLAG },
		{ "clear", no_argument, &mode_flag, CLEAR_IP_FLAG },
		{ "drop", no_argument, &mode_flag, DROP_IP_FLAG },
		{ "no-drop", no_argument, &mode_flag, UNDROP_IP_FLAG },
		{ "interface", required_argument, 0, 'i' },
		{ "program", required_argument, 0, 'p' },
		{ "ips", required_argument, 0, 'I' },
		{ "tags", required_argument, 0, 't' },
		{ "ptb-max-pps", required_argument, 0, 's' },
		{ "frags-drop", no_argument, 0, 'f' },
		{ "no-frags-drop", no_argument, 0, 'F' },
		{ "json", no_argument, 0, 'j' },
		{ "statsd", no_argument, 0, 'U'},
		{ "statsd-host", required_argument, 0, 'H' },
		{ "statsd-port", required_argument, 0, 'P' },
		{ "statsd-detach-on-exit", no_argument, 0, 'D' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	// Initialize interfaces
	memset(interfaces, 0, sizeof(interfaces));

	while ((opt =
		getopt_long(argc, argv, "i:p:I:t:hsfFjH:P:", options,
			    &option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'i':
			// Allow a IF_SEP separated list of interfaces to make systemd templates work...
			for (iface = strtok(optarg, IF_SEP); iface ; iface = strtok(NULL, IF_SEP)) {
				for (int i = 0; i < interface_count; i++) {
					if (strncmp(iface, interfaces[i].name, sizeof(interfaces[0].name)) == 0)
						errx(EXIT_FAILURE, "Duplicate interface %s", iface);
				}
				strncpy(interfaces[interface_count].name, iface, sizeof(interfaces[0].name)-1);
				interface_count++;
				if (interface_count == IF_MAX)
					errx(EXIT_FAILURE, "Too many interfaces specified.  Max is %i", IF_MAX);
			}
			break;
		case 'p':
			program = strdup(optarg);
			break;
		case 'I':
			tok = strtok(optarg, ", ;");
			while (tok != NULL) {
				ip_chain_add(&chain, tok);
				tok = strtok(NULL, ", ;");
			}
			break;
		case 't':
			tag_list = strdup(optarg);
			break;
		case 's':
			ptb_max_pps = atoi(optarg);
			break;
		case 'f':
			frags_drop = 1;
			break;
		case 'F':
			frags_drop = 0;
			break;
		case 'j':
			json = true;
			break;
		case 'S':
			break;
		case 'H':
			strncpy(statsd_host, optarg, sizeof(statsd_host)-1);
			break;
		case 'P':
			strncpy(statsd_port, optarg, sizeof(statsd_port)-1);
			break;
		case 'U':
			statsd_enable = true;
			break;
		case 'D':
			statsd_detach_on_exit = true;
			break;
		default:
			usage(0);
			break;
		}
	}

	if (program == NULL) {
		program = strdup(XDP_FILTER_PROG_O);
	}

	if (interface_count == 0)
		errx(EX_USAGE, "An --interface is required.  Use --help for more info.");

	if (statsd_enable && (mode_flag != NO_FLAG && mode_flag != ATTACH_FLAG))
		errx(EX_USAGE, "--statsd can only be combined with --attach or no other operation");

	// Create a context for each interface
	for (int i = 0; i < interface_count; i++) {
		err = filter_new_ecbpf_ctx(&interfaces[i]);
		if (err)
			goto done;
	}

	switch (mode_flag) {
	case ATTACH_FLAG:
		for (int i = 0; i < interface_count; i++) {
			err = attach(&interfaces[i], program);
			if (err)
				errx(EX_SOFTWARE, "Failed to attach to interface %s.", interfaces[i].name);
		}
		break;
	case DETACH_FLAG:
		for (int i = 0; i < interface_count; i++) {
			detach(&interfaces[i], false);
		}
		goto done; // skip ip chain stuff
		break;
	case STATUS_FLAG:
		if (json) {
			status_json(interfaces, interface_count);
		} else {
			status(interfaces, interface_count);
		}
		goto done;
		break;
	case CLEAR_STATUS_FLAG:
		for (int i = 0; i < interface_count; i++) {
			err = stats_clear(&interfaces[i]);
			if (err)
				goto done;
		}
		goto done;
		break;
	case CLEAR_IP_FLAG:
		for (int i = 0; i < interface_count; i++) {
			err = maps_clear(&interfaces[i]);
			if (err)
				goto done;
		}
		goto done;
		break;
	case DROP_IP_FLAG:
		if (chain == NULL)
			errx(EX_USAGE, "You must supply a list of IP addresses using the --ips option.");
		if (tag_list != NULL) {
			ip_chain_tag(chain, tag_list);
		}

		for (int i = 0; i < interface_count; i++) {
			maps_ip_chain_populate(&interfaces[i], chain);
		}
		goto done;
		break;
	case UNDROP_IP_FLAG:
		if (chain == NULL)
			errx(EX_USAGE, "You must supply a list of IP addresses using the --ips option.");
		for (int i = 0; i < interface_count; i++) {
			maps_ip_chain_remove(&interfaces[i], chain);
		}
		goto done;
		break;
	}

	if (ptb_max_pps != CONFIG_NO_CHANGE) {
		for (int i = 0; i < interface_count; i++) {
			config_ptb_max_pps_set(&interfaces[i], ptb_max_pps);
		}
	}

	if (frags_drop != CONFIG_NO_CHANGE) {
		for (int i = 0; i < interface_count; i++) {
			config_frags_drop_set(&interfaces[i], frags_drop);
		}
	}

	// Enter statsd loop is requested
	if (statsd_enable) {
		status_statsd(interfaces, interface_count, statsd_host, statsd_port);
		if (statsd_detach_on_exit) {
			printf("xdp_filter: Statsd logging terminated.  Detaching.\n");
			for (int i = 0; i < interface_count; i++) {
				detach(&interfaces[i], false);
			}
		}
	}

done:
	if (tag_list)
		free(tag_list);
	if (program)
		free(program);
	ip_chain_free(chain);

	for (int i = 0; i < interface_count; i++) {
		if (interfaces[i].ctx)
			ecbpf_ctx__free(interfaces[i].ctx);
		if (interfaces[i].fds)
			free(interfaces[i].fds);
	}

	return err;
}
