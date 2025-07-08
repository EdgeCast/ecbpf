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

#include <json-c/json.h> // libjson-c-dev

#include "libecbpf.h"
#include "maps.h"
#include "config.h"

/* internal functions */
void config_set(struct filter_interface *interface, struct filter_configuration *config);
void config_get(struct filter_interface *interface, struct filter_configuration *config);

/*
 * Public functions
 */
int config_init(struct filter_interface *interface) {
	int idx = 0;
	int err = 0;
	struct filter_configuration tmp = {};

	err = maps_open(interface);
	if (err) {
		return err;
	}

	tmp.frags_drop = false;
	tmp.ptb_send = true;
	tmp.ptb_max_pps = 200;

	err = bpf_map_update_elem(interface->fds->config_fd, &idx, &tmp, BPF_ANY);

	if (err) {
		fprintf(stderr, "Failed to init config on interface '%s': %m\n", interface->name);
	}

	return err;
}

int config_ptb_max_pps_set(struct filter_interface *interface, int ptb_max_pps) {
	int err = 0;
	struct filter_configuration config;

	config_get(interface, &config);
	if (ptb_max_pps > 0) {
		config.ptb_send = true;
		config.ptb_max_pps = ptb_max_pps;
	} else {
		config.ptb_send = false;
		config.ptb_max_pps = 0;
	}
	config_set(interface, &config);

	return err; // Since config_set/get are fatal, we just return 0 for now
}


int config_frags_drop_set(struct filter_interface *interface, int frags_drop) {
	int err = 0;
	struct filter_configuration config;

	config_get(interface, &config);

	if (frags_drop) {
		config.frags_drop = true;
	} else {
		config.frags_drop = false;
	}

	config_set(interface, &config);

	return err; // Since config_set/get are fatal, we just return 0 for now
}


void config_print(struct filter_interface *interface) {
	struct filter_configuration tmp;
	int idx = 0;
	int err;

	err = maps_open(interface);
	if (err) {
		errx(EX_SOFTWARE, "Failed to open maps for interface '%s'", interface->name);
	}

	err = bpf_map_lookup_elem(interface->fds->config_fd, &idx, &tmp);

	if (err) {
		errx(EX_SOFTWARE, "Failed to lookup configuration on interface '%s': %m", interface->name);
	}

	printf("Current Configuration:\n\n");
	printf("frags_drop? %s\n", tmp.frags_drop ? "true" : "false");
	printf("ptb_send? %s\n", tmp.ptb_send ? "true" : "false");
	printf("ptb_max_pps: %d\n", tmp.ptb_max_pps);
	printf("\n");
}

void config_json(struct filter_interface *interface, struct json_object *root_obj) {
	struct filter_configuration tmp;
	int idx = 0;
	struct json_object *config_obj;
	int err;

	err = maps_open(interface);
	if (err) {
		errx(EX_SOFTWARE, "Failed to open maps for interface '%s'", interface->name);
	}

	err = bpf_map_lookup_elem(interface->fds->config_fd, &idx, &tmp);

	if (err) {
		errx(EX_SOFTWARE, "Failed to lookup configuration for interface '%s': %m", interface->name);
	}

	config_obj = json_object_new_object();
	json_object_object_add(root_obj, "configuration", config_obj);

	json_object_object_add(config_obj, "frags_drop", json_object_new_boolean(tmp.frags_drop));
	json_object_object_add(config_obj, "ptb_send", json_object_new_boolean(tmp.ptb_send));
	json_object_object_add(config_obj, "ptb_max_pps", json_object_new_int(tmp.ptb_max_pps));
}

/*
 *   functions
 */
void config_set(struct filter_interface *interface, struct filter_configuration *config) {
	int idx = 0;
	int err;

	err = maps_open(interface);
	if (err) {
		errx(EX_SOFTWARE, "Failed to open maps for interface '%s'", interface->name);
	}

	err = bpf_map_update_elem(interface->fds->config_fd, &idx, config, BPF_ANY);

	if (err) {
		errx(EX_SOFTWARE, "Failed to set config on interface '%s': %m", interface->name);
	}
}

void config_get(struct filter_interface *interface, struct filter_configuration *config) {
	struct filter_configuration tmp;
	int idx = 0;
	int err;

	err = maps_open(interface);
	if (err) {
		errx(EX_SOFTWARE, "Failed to open maps for interface '%s'", interface->name);
	}

	err = bpf_map_lookup_elem(interface->fds->config_fd, &idx, config);

	if (err) {
		errx(EX_SOFTWARE, "Failed to lookup configuration on interface '%s': %m", interface->name);
	}
}
