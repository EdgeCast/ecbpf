#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "libecbpf.h"
#include "xdp_sampler.h"
#include "configuration.h"

static int configuration_populate_host_info(struct sampler_cfg *ctx);

struct sampler_cfg *configuration_new() {
	int res;
	struct sampler_cfg *cfg = calloc(1, sizeof(struct sampler_cfg));
	if (cfg == NULL)
		errx(EXIT_FAILURE, "Failed to allocate memory in configuration_new");

	// debug off
	cfg->debug = false;

	// default port for zmq
	strncpy(cfg->port, "12354", sizeof(cfg->port)-1);

	// statsd defaults
	cfg->statsd_enable = false;
	strncpy(cfg->statsd_host, LIBECBPF_STATSD_HOST, sizeof(cfg->statsd_host)-1);
	strncpy(cfg->statsd_port, LIBECBPF_STATSD_PORT, sizeof(cfg->statsd_port)-1);

	// populate hostname, pop, etc
	res = configuration_populate_host_info(cfg);
	if (res) {
		errx(EXIT_FAILURE, "Failed to get host information, aborting");
	}

	return cfg;
}

void configuration_free(struct sampler_cfg *cfg) {
	free(cfg);
}

static int configuration_populate_host_info(struct sampler_cfg *ctx) {
	char hostbuf[HOST_NAME_MAX];
	char *idx = NULL;
	char *curtok;

	if(gethostname(hostbuf, sizeof(hostbuf))) {
		fprintf(stderr, "Failed to get hostname: %m\n");
		return EX_SOFTWARE;
	}

	// Hostname will be directorN.pop
	idx = hostbuf;
	curtok = strsep(&idx, ".");
	strncpy(ctx->hostname, curtok, sizeof(ctx->hostname)-1);

	// pop was found
	if (idx != NULL) {
		// curtok should be null
		curtok = strsep(&idx, ".");
		strncpy(ctx->pop, curtok, sizeof(ctx->pop)-1);
	} else {
		fprintf(stderr, "No pop code found in hostname\n");
		return EX_SOFTWARE;
	}

	// Grab the srv type
	FILE *fp = fopen(SRV_TYPE_FILE, "r");
	if (fp != NULL) {
		char *line = NULL;
		size_t linecap = 0;
		ssize_t linelen;
		linelen = getline(&line, &linecap, fp);
		if (linelen < 0) {
			fprintf(stderr, "Failed to get line from srvinfo\n");
			return EX_SOFTWARE;
		}

		// strip newline
		char *p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';

		// copy in
		strncpy(ctx->srvtype, line, sizeof(ctx->srvtype) - 1);
		// free line
		free(line);
		fclose(fp);
	} else {
		fprintf(stderr, "No srvtype found in %s\n", SRV_TYPE_FILE);
		return EX_SOFTWARE;
	}

	return EX_OK;
}
