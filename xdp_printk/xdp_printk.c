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

#include "libecbpf.h"
#include "xdp_printk.h"
#include "rootmaps.h"


static int mode_flag;

enum flags {
	ATTACH_FLAG,
	DETACH_FLAG,
};

void attach(struct ecbpf_ctx *ctx, char *program);
void detach(struct ecbpf_ctx *ctx);
void usage(int ret);

void usage(int ret) {

	printf("xdp_printk: Example noise!\n\n"
		   "   --attach: Attach program\n"
		   "   --detach: Detach program\n"
		   "   --interface <int> - Must have root array loaded.\n"
           "   --program <xdp_printk_kern.o> - Full path to xdp_printk_kern.o\n");
	exit(ret);
}

void attach(struct ecbpf_ctx *ctx, char *program) {

	int id;
	int err;
	/* check if a printk is already loaded */
	id = ecbpf__subprogram_slot_prog_id(ctx, XDP_PROG_ARRAY_IDX);
	if (id >= 0) {
		errx(EX_USAGE, "Program already in slot");
	}

	err = ecbpf__subprogram_open(ctx, program);
	if (err) {
		errx(EX_SOFTWARE, "Failed to load subprogram from %s", program);
	}

	err = ecbpf__subprogram_attach(ctx, xstr(XDP_PRINTK_PROG_NAME), XDP_PROG_ARRAY_IDX);
	if (err) {
		errx(EX_SOFTWARE, "Failed to attach subprogram");
	}
}

void detach(struct ecbpf_ctx *ctx) {
	int err;

	err = ecbpf__subprogram_detach(ctx, XDP_PROG_ARRAY_IDX);

	if (err)
		errx(EX_SOFTWARE, "Failed to detach from root array");
}

int main(int argc, char **argv) {
	int err = 0;
	int map_fd;

	struct ecbpf_ctx *ctx;
	char name[256];
	char *interface = NULL;
	char *program = NULL;
	char *port = NULL;
	int opt;
	int option_index = 0;

	struct perf_buffer_opts perf_buffer_opts = {};

	struct option options[] = {
		{ "attach", no_argument, &mode_flag, ATTACH_FLAG },
		{ "detach", no_argument, &mode_flag, DETACH_FLAG },
		{ "interface", required_argument, 0, 'i' },
		{ "program", required_argument, 0, 'P' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt =
		getopt_long(argc, argv, "i:P:h", options,
			    &option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'i':
			interface = strdup(optarg);
			break;
		case 'P':
			program = strdup(optarg);
			break;
		default:
			usage(0);
			break;
		}
	}

	/* Setup the ecbpf context */
	ctx = ecbpf_ctx__new();

	if (program == NULL) {
		program = strdup(XDP_PRINTK_PROG_O);
	}

	if (interface == NULL) {
		fprintf(stderr, "Interface must be supplied\n");
		err = EX_USAGE;
		goto done;
	}

	ecbpf_ctx__set_interface(ctx, interface);

	/* Make sure interface has a root array */
	if (ecbpf__check_root_program(ctx)) {
		err = EX_CONFIG;
		fprintf(stderr, "Root program array not attached to interface %s", interface);
		goto done;
	}

	switch (mode_flag) {
	case ATTACH_FLAG:
		attach(ctx, program);
		break;
	case DETACH_FLAG:
		detach(ctx);
		break;
	}

done:
	if (interface)
		free(interface);
	if (program)
		free(program);
	ecbpf_ctx__free(ctx);

	return err;
}
