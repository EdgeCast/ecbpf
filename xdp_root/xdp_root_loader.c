/*
 * Loader for xdp root
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <ftw.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <net/if.h>
#include <time.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <sys/mount.h>

#include <json-c/json.h> // libjson-c-dev

#include "libecbpf.h"
#include "rootmaps.h"

enum flags {
	ATTACH_FLAG,
	DETACH_FLAG,
	TRACE_FLAG,
	STATUS_FLAG
};

struct iflist {
	char *ifname;
	struct iflist *next;
	struct iflist *head;
};

#define XDP_ROOT_PROG_O "xdp_root_kern.o"
#define XDP_ROOT_NOP_O "xdp_root_nop_kern.o"
#define KERNEL_TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define IF_SEP ",-:" // Separators for interface list

void usage(char *message);
void trace();
void attach(char *filename, char *interface, bool generic, bool force);
void detach(char *filename, char *interface, bool generic, bool nop);
void status(char *interface);
void json_status(struct iflist *);
void clear_status(struct iflist *);

void usage(char *message)
{
	int status = EX_OK;
	if (message) {
		status = EX_USAGE;
		fprintf(stderr, "%s\n", message);
	}

	fprintf(stderr,
		"xdp_root_loader: Load and check root array\n"
		"  --trace: Open the kernel debug trace pipe and print to screen.\n"
		"  --attach: Attach root array.\n"
		"  --detach: Detach root array.\n"
		"  --nop: Load a XDP NOP program upon detach to keep ixgbe in XDP mode."
		"  --interface <someif>: Interface to use.\n"
		"  --generic: Use XDP generic mode instead of driver.\n"
		"  --force: Force loading root array.\n"
		"  --status: Root array status.\n"
		"  --json: Display information in JSON format (currently applies to status).\n"
		"  --clear: Clear xdp statistics (currently applies to status).\n"
		"  --filename <xdp_root.o>: Root array program object file.\n");
	exit(status);
}

// Watch the kernel debug pipe
void trace() {

	FILE *fp;
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;

	fp = fopen(KERNEL_TRACE_PIPE, "r");

	if (!fp) {
		fprintf(stderr, "Failed to open kernel trace pipe (are you root?): %m\n");
		exit(EX_NOPERM);
	}

	while ((linelen = getline(&line, &linecap, fp)) > 0)
		fwrite(line, linelen, 1, stdout);

	free(line);
	fclose(fp);
}

void attach(char *filename, char *interface, bool generic, bool force) {
	int err;
	struct ecbpf_ctx *ctx = ecbpf_ctx__new();

	if (generic)
		ecbpf_ctx__set_xdp_mode_generic(ctx);

	if (force) {
		err = ecbpf_ctx__set_force_load(ctx, true);
		if (err) {
			errx(EX_SOFTWARE, "Failed to set force load");
		}
	}

	err = ecbpf_ctx__set_interface(ctx, interface);
	if (err) {
		errx(EX_SOFTWARE, "Invalid interface: %s", interface);
	}

	err = ecbpf__load_root_program(ctx, filename, xstr(ROOT_PROG_NAME));
	if (err) {
		errx(EX_SOFTWARE, "Failed to load root program '%s' on interface %s", filename, interface);
	}

	err = ecbpf__attach_root_program(ctx);
	if (err) {
		errx(EX_SOFTWARE, "Failed to attach root program on interface %s", interface);
	}

	ecbpf_ctx__free(ctx);
}

void detach(char *filename, char *interface, bool generic, bool nop) {
	int err;
	struct ecbpf_ctx *ctx = ecbpf_ctx__new();

	if (generic)
		ecbpf_ctx__set_xdp_mode_generic(ctx);

	err = ecbpf_ctx__set_interface(ctx, interface);
	if (err) {
		// Print an error instead of exiting to allow for a list of detaches to continue
		fprintf(stderr, "Invalid interface: %s", interface);
		goto done;
	}

	if (nop) {
		err = ecbpf__load_root_program(ctx, filename, xstr(ROOT_PROG_NOP_NAME));
		if (err) {
			errx(EX_SOFTWARE, "Failed to load root NOP program '%s' on interface %s", filename, interface);
		}
	}

	err = ecbpf__detach_root_program(ctx);
	if (err) {
		// Print an error instead of exiting to allow for a list of detaches to continue
		fprintf(stderr, "Failed to detach root program on interface %s", interface);
		goto done;
	}

done:
	ecbpf_ctx__free(ctx);
}

void status(char *interface) {
	int err;
	int prog_id;
	char name[256];
	char tmbuf[128];
	time_t load_time;
	struct xdp_stats stats;

	struct ecbpf_ctx *ctx = ecbpf_ctx__new();

	printf("Inferface %s status:\n", interface);

	err = ecbpf_ctx__set_interface(ctx, interface);
	if (err) {
		printf("Invalid interface: %s\n", interface);
		goto done;
	}

	err = ecbpf__check_root_program(ctx);
	if (err) {
		if (err == -EACCES) {
			errx(EX_USAGE, "Need to be root to determine root array status.\n");
		} else {
			printf("Root array not attached to interface %s.\n", interface);
		}
		goto done;
	}

	printf("SLOT | %-5s | %-24s | %-35s ", "ID", "NAME", "LOAD TIME");
	for (int i = 0; i < STAT_XDP_MAX; i++)
		printf(" | %-16s", xdp_stat_names[i]);
	printf("\n");

	for (int slot = 0 ; slot < SUBPROGRAM_MAX ; slot++) {
		prog_id = ecbpf__subprogram_slot_prog_id(ctx, slot);

		printf("%4i | ", slot);
		if (prog_id >= 0) {
			strcpy(name, "*no name*");
			load_time = 0;
			ecbpf__subprogram_slot_name(ctx, slot, name, sizeof(name));
			ecbpf__subprogram_slot_load_time(ctx, slot, &load_time);
			strftime(tmbuf, sizeof(tmbuf), "%a, %d %b %Y %T %z",
					gmtime(&load_time));
			printf("%5i | %-24s | %-35s ", prog_id, name, tmbuf);
		} else {
			printf("%5s | %-24s | %-35s ", "-", "-", "-");
		}

		err = ecbpf__subprogram_slot_statistics(ctx, slot, &stats);
		if (err)
			goto done;

		for (int i = 0; i < STAT_XDP_MAX; i++)
			printf(" | %16lu", stats.action_count[i]);
		printf("\n");
	}

done:
	printf("\n");
	ecbpf_ctx__free(ctx);
}

void json_status(struct iflist *iflist) {
	char name[256];
	char tmbuf[128];
	int prog_id;
	int err;
	uint64_t count[STAT_XDP_MAX];
	time_t load_time;
	struct xdp_stats stats;
	struct ecbpf_ctx *ctx;
	struct json_object *rootobj, *ifobj, *subprogsobj, *slotobj, *statsobj;

	rootobj = json_object_new_object();

	for (struct iflist *cur = iflist->head; cur != NULL ; cur = cur->next) {
		// Clear the stats for this interface
		for (int cidx = 0; cidx < STAT_XDP_MAX ; cidx++)
			count[cidx] = 0;

		ctx = ecbpf_ctx__new();
		err = ecbpf_ctx__set_interface(ctx, cur->ifname);
		if (err) {
			printf("Invalid interface: %s\n", cur->ifname);
			ecbpf_ctx__free(ctx);
			continue;
		}

		// Add the interface to the root object
		ifobj = json_object_new_object();
		json_object_object_add(rootobj, cur->ifname, ifobj);

		err = ecbpf__check_root_program(ctx);
		if (err) {
			if (err == -EACCES) {
				errx(EX_USAGE, "Need to be root to determine root array status.\n");
			}
			json_object_object_add(ifobj, "root_loaded", json_object_new_boolean(false));
			ecbpf_ctx__free(ctx);
			continue;
		}

		json_object_object_add(ifobj, "root_loaded", json_object_new_boolean(true));
		subprogsobj = json_object_new_array();
		json_object_object_add(ifobj, "subprograms", subprogsobj);

		for (int slot = 0 ; slot < SUBPROGRAM_MAX ; slot++) {
			prog_id = ecbpf__subprogram_slot_prog_id(ctx, slot);
			slotobj = json_object_new_object();
			json_object_object_add(slotobj, "slot", json_object_new_int(slot));

			if (prog_id >= 0) {
				// prog_loaded key
				json_object_object_add(slotobj, "prog_loaded", json_object_new_boolean(true));

				// name key
				strcpy(name, "no name");
				load_time = 0;
				ecbpf__subprogram_slot_name(ctx, slot, name, sizeof(name));
				json_object_object_add(slotobj, "name", json_object_new_string(name));

				// load_time key
				ecbpf__subprogram_slot_load_time(ctx, slot, &load_time);
				strftime(tmbuf, sizeof(tmbuf), "%a, %d %b %Y %T %z",
					gmtime(&load_time));
				json_object_object_add(slotobj, "load_time", json_object_new_string(tmbuf));
			} else {
				json_object_object_add(slotobj, "prog_loaded", json_object_new_boolean(false));
			}

			// Slot statstics
			err = ecbpf__subprogram_slot_statistics(ctx, slot, &stats);
			if (err)
				goto done;

			statsobj = json_object_new_object();
			json_object_object_add(slotobj, "statistics", statsobj);

			for (int i = 0; i < STAT_XDP_MAX; i++) {
				count[i] += stats.action_count[i];
				/* The version of libjson-c that ships with Bionic does not
				 * include the json_object_new_uint64 function.  Since these
				 * are counters, we will mask the most significant bit for now.
				 */
				json_object_object_add(statsobj,
						xdp_stat_names[i],
						json_object_new_int64(stats.action_count[i] & UINT64_MAX >> 1));
			}

			json_object_array_add(subprogsobj, slotobj);
		}


		// Add in interface totals
		statsobj = json_object_new_object();
		strcpy(name, "statistics");
		for (int i = 0; i < STAT_XDP_MAX; i++) {
			/* The version of libjson-c that ships with Bionic does not
			 * include the json_object_new_uint64 function.  Since these
			 * are counters, we will mask the most significant bit for now.
			 */
			json_object_object_add(statsobj,
						xdp_stat_names[i],
						json_object_new_int64(count[i] & UINT64_MAX >> 1));
		}
		json_object_object_add(ifobj, name, statsobj);

		ecbpf_ctx__free(ctx);
	}

	printf("%s\n", json_object_to_json_string_ext(rootobj, JSON_C_TO_STRING_PRETTY));

	json_object_put(rootobj);
done:
	return;
}

void clear_status(struct iflist *iflist) {
	int err;
	struct ecbpf_ctx *ctx;

	for (struct iflist *cur = iflist->head; cur != NULL ; cur = cur->next) {
		ctx = ecbpf_ctx__new();
		err = ecbpf_ctx__set_interface(ctx, cur->ifname);
		if (err) {
			printf("Invalid interface: %s\n", cur->ifname);
			ecbpf_ctx__free(ctx);
			continue;
		}

		err = ecbpf__check_root_program(ctx);
		if (err) {
			printf("No root program on interface: %s\n", cur->ifname);
			ecbpf_ctx__free(ctx);
			continue;
		}

		for (int slot = 0 ; slot < SUBPROGRAM_MAX ; slot++) {
			// Slot statstics
			err = ecbpf__subprogram_slot_statistics_clear(ctx, slot);
			if (err) {
				printf("Problem clearing statistics on interface: %s slot: %i\n", cur->ifname, slot);
				continue;
			}
		}
		printf("Cleared statistics on interface: %s\n", cur->ifname);
		ecbpf_ctx__free(ctx);
	}	
}

void iflist_free(struct iflist *iflist) {

	if (iflist == NULL)
		return;

	struct iflist *cur = iflist->head;
	struct iflist *del;

	while (cur != NULL) {
		del = cur;
		cur = cur->next;
		free(del->ifname);
		free(del);
	}
}

struct iflist * iflist_add(struct iflist* iflist, char* ifname) {
	if (strlen(ifname) >= (IFNAMSIZ-1)) { // IFNAMSIZ includes the null
		errx(EXIT_FAILURE, "Invalid interface: %s", ifname);
	}

	if (iflist == NULL) {
		iflist = calloc(1, sizeof(struct iflist));
		iflist->head = iflist;
		iflist->ifname = strdup(ifname);
		return iflist;
	}

	for (struct iflist *c = iflist->head; c != NULL; c = c->next) {
		if (strcmp(ifname, iflist->ifname) == 0)
			errx(EXIT_FAILURE, "Duplicate interface %s", ifname);
	}

	iflist->next = calloc(1, sizeof(struct iflist));
	iflist->next->head = iflist->head;
	iflist = iflist->next;
	iflist->ifname = strdup(ifname);

	return iflist;
}

/*
 * Populate an iflist with all interfaces on the system.
 */
struct iflist *iflist_default() {
	struct iflist *iflist = NULL;
	struct if_nameindex *if_names, *cur;


	if_names = if_nameindex();
	if (if_names == NULL) {
		errx(EXIT_FAILURE, "Failed to get list of interface names: if_nameindex: %m");
	}

	for (cur = if_names; ! (cur->if_index == 0 && cur->if_name == NULL) ; cur++) {
		// Only add eth or en
		if (strncmp(cur->if_name, "en", 2) == 0 ||
			strncmp(cur->if_name, "eth", 3) == 0)
			iflist = iflist_add(iflist, cur->if_name);
	}
	
	if_freenameindex(if_names);
	return iflist;
}


static int mode_flag;
int main(int argc, char **argv)
{
	struct option options[] = {
		{ "generic", no_argument, 0, 'g' },
		{ "interface", required_argument, 0, 'i' },
		{ "filename", required_argument, 0, 'f' },
		{ "attach", no_argument, &mode_flag, ATTACH_FLAG },
		{ "detach", no_argument, &mode_flag, DETACH_FLAG },
		{ "nop", no_argument, 0, 'n'},
		{ "force", no_argument, 0, 'F' },
		{ "help", no_argument, 0, 'h' },
		{ "status", no_argument, &mode_flag, STATUS_FLAG},
		{ "stats", no_argument, &mode_flag, STATUS_FLAG}, // Allow for status or stats
		{ "json", no_argument, 0, 'j' }, // status as json
		{ "clear", no_argument, 0, 'c' }, // clear status statistics
		{ "debug", no_argument, 0, 'd' },
		{ "trace", no_argument, &mode_flag, TRACE_FLAG},
		{ 0, 0, 0, 0 }
	};

	struct ecbpf_ctx *ctx;
	char *filename = NULL;
	char *iface;
	struct iflist *iflist = NULL;
	bool generic = false;
	bool force = false;
	bool debug = false;
	bool json = false;
	bool clear = false;
	bool nop = false;
	int opt;
	int err;
	int option_index = 0;

	int opt_status = 0;

	if (geteuid() != 0) {
		errx(EX_USAGE, "Please run as root to ensure access to bpf maps in /sys/fs/bpf.");
	}

	while ((opt =
		getopt_long(argc, argv, "gi:f:Fhsdtn", options,
			    &option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'g':
			generic = true;
			break;
		case 'd':
			ecbpf_log_set_debug();
			break;
		case 'j':
			json = true;
			break;
		case 'c':
			clear = true;
			break;
		case 'i':
			// Allow a dash separated list of interfaces to make systemd templates work...
			for (iface = strtok(optarg, IF_SEP); iface ; iface = strtok(NULL, IF_SEP)) {
				iflist = iflist_add(iflist, iface);
			}
			break;
		case 'f':
			filename = strdup(optarg);
			break;
		case 'F':
			force = true;
			break;
		case 'n':
			nop = true;
			break;
		case 'h':
		default:
			usage(NULL);
			break;
		}
	}


	// Default to all interfaces for status or detach
	if (iflist == NULL && (mode_flag == DETACH_FLAG || mode_flag == STATUS_FLAG)) {
		iflist = iflist_default();
	}


	if (mode_flag != TRACE_FLAG && iflist == NULL) {
		usage("You need to supply an --interface");
	}

	switch (mode_flag) {
	case ATTACH_FLAG:
		// Default to the packaged loader
		if (filename == NULL) {
			filename = strdup(XDP_ROOT_PROG_O);
		}
		for (struct iflist *cur = iflist->head; cur != NULL; cur = cur->next)
			attach(filename, cur->ifname, generic, force);
		break;
	case DETACH_FLAG:
		// Default to the packaged loader
		if (filename == NULL) {
			filename = strdup(XDP_ROOT_NOP_O);
		}
		for (struct iflist *cur = iflist->head; cur != NULL; cur = cur->next)
			detach(filename, cur->ifname, generic, nop);
		break;
	case TRACE_FLAG:
		trace();
		break;
	case STATUS_FLAG:
		if (clear) {
			clear_status(iflist);
		} else if (json) {
			json_status(iflist);
		} else {
			for (struct iflist *cur = iflist->head; cur != NULL; cur = cur->next)
				status(cur->ifname);
		}
		break;
	default:
		usage("This shouldn't happen");
		break;
	}

	iflist_free(iflist);
	free(filename);

	return EX_OK;
}
