#define _GNU_SOURCE // asprintf, pthread_setname_np
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits.h>
#include <zmq.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include "libecbpf.h"

#include "stats.h"
#include "xzmq.h"
#include "xdp_sampler.h"
#include "rootmaps.h"
#include "configuration.h"
#include "packet_sample.pb-c.h"

#define IF_MAX 8 // Max number of interfaces for command line utilities, somewhat arbitrary
#define IF_SEP ",-:" // Separators for interface list

// Globals
atomic_int EXIT_FLAG = 0;
atomic_long SEQUENCE = 0; // Packet sequence
void *zmq_context;

struct sampler_ctx {
	char interface[IFNAMSIZ];
	char hostname[HOST_NAME_MAX];
	char name[16];
	char pop[256];
	char srvtype[256];
	bool debug;

	struct stats_ctx *stats_ctx;

	pthread_t tid;
	struct sampler_ctx *next;

	void *push_sock;
};

/* Thread to watch perf ring */
void* watch_perf(void *data);

struct sampler_ctx *sampler_ctx_new(struct sampler_cfg *cfg, char* interface, struct sampler_ctx *next) {
	int res;
	struct sampler_ctx *ctx = calloc(1, sizeof(struct sampler_ctx));
	if (ctx == NULL)
		errx(EXIT_FAILURE, "Failed to allocate memory in sampler_ctx_new");

	strncpy(ctx->interface, interface, sizeof(ctx->interface)-1);
	strncpy(ctx->hostname, cfg->hostname, sizeof(ctx->hostname)-1);
	strncpy(ctx->pop, cfg->pop, sizeof(ctx->pop)-1);
	strncpy(ctx->srvtype, cfg->srvtype, sizeof(ctx->srvtype)-1);
	snprintf(ctx->name, sizeof(ctx->name), "samp-%s", interface);

	ctx->debug = cfg->debug;

	ctx->stats_ctx = stats_new(interface, cfg);
	if (ctx->stats_ctx == NULL) {
		errx(EXIT_FAILURE, "Failed to create new stats context for interface %s", interface);
	}

	if (next != NULL)
		ctx->next = next;
	else
		ctx->next = NULL;

	/* Setup the zmq socket */
	ctx->push_sock = zmq_socket(zmq_context, ZMQ_PUSH);
	int timeout = 10000;
	res = zmq_setsockopt(ctx->push_sock, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));  // Belt and suspenders to prevent blocking on exit
	if (res != 0) {
		err(EXIT_FAILURE, "Failed set zmq push socket options");
	}
	res = zmq_connect(ctx->push_sock, PUSH_PULL_URL);
	if (res != 0) {
		errx(EXIT_FAILURE, "Failed to setup zmq push socket: %m");
	}

	return ctx;
}

void sampler_ctx_free(struct sampler_ctx *ctx) {
	stats_free(ctx->stats_ctx);
	zmq_close(ctx->push_sock);
	free(ctx);
}

void sig_handler(int signo) {
	EXIT_FLAG = 1;
}

/*
 * Main logic for handling packets
 */
void handle_perf_event(void *ctx, int cpu, void *data, __u32 size) {
	int sent;
	struct sampler_ctx *sampler_ctx = (struct sampler_ctx *) ctx;
	struct xdp_sample_metadata *e = data;
	void *buf;
	struct timespec ts;
	size_t length;

	PacketSample__PacketSample sample = PACKET_SAMPLE__PACKET_SAMPLE__INIT; // Container for packet
	PacketSample__PacketSample__Packet packet = PACKET_SAMPLE__PACKET_SAMPLE__PACKET__INIT; // Packet capture data
	PacketSample__PacketSample__HostInfo host_info = PACKET_SAMPLE__PACKET_SAMPLE__HOST_INFO__INIT;
	PacketSample__PacketSample__PacketCommon packet_common = PACKET_SAMPLE__PACKET_SAMPLE__PACKET_COMMON__INIT;

	if (e->cookie != MAGIC) {
		fprintf(stderr, "Unexpected cookie: %x\n", e->cookie);
		return;
	}

	// increment stats
	stats_incr(sampler_ctx->stats_ctx);
	SEQUENCE++; // Atomic packet sequence for all packets emitted

	clock_gettime(CLOCK_REALTIME, &ts);

	// Packet fields
	packet.tv_sec = ts.tv_sec;
	packet.tv_nsec = ts.tv_nsec;
	packet.len = e->len; // length of orginal packet
	packet.pkt.data = e->pkt_data;
	packet.pkt.len = e->caplen;

	// Packet Sample Metadata
	packet.sampling_probability_reciprocal = e->sampling_probability_reciprocal;
	packet.sequence = SEQUENCE;
	packet.xdp_action_source = e->xdp_action_source;
	packet.xdp_action = e->xdp_action;
	packet.xdp_action_code = e->xdp_action_code;
	packet.xdp_action_meta = e->xdp_action_meta;

	// HostInfo fields
	host_info.hostname = sampler_ctx->hostname;
	host_info.pop = sampler_ctx->pop;
	host_info.srvtype = sampler_ctx->srvtype;

	// PacketCommon fields
	packet_common.interface = sampler_ctx->interface;
	packet_common.link = PACKET_SAMPLE__PACKET_SAMPLE__LINK_TYPE__LINKTYPE_ETHERNET;

#ifdef bionic
	// Bionic has protoc-c 1.2.1 which is before full proto3 support.
	packet.has_tv_sec = true;
	packet.has_tv_nsec = true;
	packet.has_len = true;
	packet.has_pkt = true;
	packet.has_sampling_probability_reciprocal = true;
	packet.has_sequence = true;
	packet_common.has_link = true;
#endif

	// Sample fields
	sample.packet = &packet;
	sample.host_info = &host_info;
	sample.packet_common = &packet_common;

	// Pack the protobuf
	length = packet_sample__packet_sample__get_packed_size(&sample);
	buf = malloc(length);
	if (buf == NULL)
		errx(EXIT_FAILURE, "Failed to allocate memory in handle_perf_event");

	packet_sample__packet_sample__pack(&sample, buf);

	// Launch it
	sent = zmq_send(sampler_ctx->push_sock, buf, length, 0);

	if (sent < 0) {
		errx(EXIT_FAILURE, "zmq_send failed with %i: %m\n", sent);
	}

	free(buf);
}

void usage(int ret) {
	printf("xdp_sampler: Sample packets!\n\n"
		   "   --debug - Print additional debug information\n"
		   "   --port <port> - Port to listen to\n"
		   "   --statsd - Send stats to statsd\n"
		   "   --statsd-host <host> - Host to send statsd to, defaults to localhost\n"
		   "   --statsd-port <port> - Host to send statsd to, defaults to 8125\n"
		   "   --interface <ifname> - Interfaces to sample packets on.  Must have root array loaded.  Can be comma or dash separated list.\n");
	exit(ret);
}

int main(int argc, char **argv) {

	struct sampler_cfg *cfg = configuration_new();
	char interfaces[IF_MAX][IFNAMSIZ];
	int interface_count = 0;
	int res;
	int opt;
	int option_index = 0;
	char *iface;
	struct sigaction sig_act;

	struct option options[] = {
		{ "interface", required_argument, 0, 'i' },
		{ "statsd", no_argument, 0, 's' },
		{ "statsd-host", required_argument, 0, 'H' },
		{ "statsd-port", required_argument, 0, 'S' },
		{ "port", required_argument, 0, 'p' },
		{ "help", no_argument, 0, 'h' },
		{ "debug", no_argument, 0, 'd' },
		{ 0, 0, 0, 0 }
	};

	while ((opt =
		getopt_long(argc, argv, "i:p:o:hdsH:S:", options,
			    &option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'i':
			// Allow a IF_SEP separated list of interfaces to make systemd templates work...
			for (iface = strtok(optarg, IF_SEP); iface ; iface = strtok(NULL, IF_SEP)) {
				for (int i = 0; i < interface_count; i++) {
					if (strncmp(iface, interfaces[i], sizeof(interfaces[0])) == 0)
						errx(EXIT_FAILURE, "Duplicate interface %s", iface);
				}
				strncpy(interfaces[interface_count], iface, sizeof(interfaces[0])-1);
				interface_count++;
				if (interface_count == IF_MAX)
					errx(EXIT_FAILURE, "Too many interfaces specified.  Max is %i", IF_MAX);
			}
			break;
		case 'p':
			strncpy(cfg->port, optarg, sizeof(cfg->port)-1);
			break;
		case 'd':
			cfg->debug = true;
			break;
		case 's':
			cfg->statsd_enable = true;
			break;
		case 'H':
			strncpy(cfg->statsd_host, optarg, sizeof(cfg->statsd_host)-1);
			break;
		case 'S':
			strncpy(cfg->statsd_port, optarg, sizeof(cfg->statsd_port)-1);
			break;
		default:
			usage(0);
			break;
		}
	}

	if (interface_count == 0) {
		fprintf(stderr, "Missing required argument\n");
		usage(1);
	}

	zmq_context = zmq_ctx_new(); // must come before xzmq stuff

	/* Setup signal handler */
	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;
	sig_act.sa_handler = sig_handler;
	sigaction(SIGTERM, &sig_act, NULL);
	sigaction(SIGINT, &sig_act, NULL);

	/* Launch Threads */

	/* Setup the zmq publisher */
	struct xzmq_ctx *xzctx = xzmq_ctx_new(cfg->port);
	if (xzctx == NULL)
		errx(EXIT_FAILURE, "Failed to create xzmq_ctx");
	xzmq_start(xzctx);

	struct sampler_ctx *ctx = NULL, *prev;

	/* Start Watching */
	for (int i = 0; i < interface_count; i++) {
		ctx = sampler_ctx_new(cfg, interfaces[i], ctx);

		/* Start stats threads */
		stats_start(ctx->stats_ctx);

		res = pthread_create(&ctx->tid, NULL, watch_perf, (void*)ctx);
		if (res) {
			errx(EXIT_FAILURE, "Failed to start watch_perf thread: %s", strerror(res));
		}

		res = pthread_setname_np(ctx->tid, ctx->name);
		if (res) {
			err(EXIT_FAILURE, "Failed to set watch_perf thread name: %s", strerror(res));
		}

	}

	/* Wait on threads */
	while (ctx != NULL) {
		res = pthread_join(ctx->tid, NULL);
		if (res) {
			errx(EXIT_FAILURE, "Joining thread %s failed: %m\n", ctx->name);
		}
		if (cfg->debug)
			printf("Joined watcher thread %s\n", ctx->name);
		/* Cleanup */
		stats_stop(ctx->stats_ctx); // Stop stats threads
		prev = ctx;
		ctx = ctx->next;
		sampler_ctx_free(prev);
	}

	// Wait for zmq publisher to die
	xzmq_stop(xzctx);
	xzmq_ctx_free(xzctx);

	// on exit of watchers
	configuration_free(cfg);
	zmq_ctx_destroy(zmq_context);
}

void* watch_perf(void *data) {
	struct sampler_ctx *sampler_ctx = (struct sampler_ctx *) data;
	int res;
	int map_fd;
	char name[256];
	struct ecbpf_ctx *ctx = NULL; // Must be initialized for goto done
	struct perf_buffer *perf_buffer = NULL; // Must be initialized for goto done


	/* Setup the ecbpf context */
	ctx = ecbpf_ctx__new();
	ecbpf_ctx__set_pinned_map(ctx, xstr(XDP_SAMPLER_MAP_NAME));
	if(ecbpf_ctx__set_interface(ctx, sampler_ctx->interface)) {
		fprintf(stderr, "Problem with interface %s\n", sampler_ctx->interface);
		goto done;
	}

	if (ecbpf__check_root_program(ctx)) {
		fprintf(stderr, "Root program array not attached to interface %s\n", sampler_ctx->interface);
		goto done;
	}

	// Setup the perf buffer
	map_fd = ecbpf__get_map_fd(ctx, xstr(XDP_SAMPLER_MAP_NAME));
	if (map_fd < 0) {
		res = EXIT_FAILURE;
		fprintf(stderr, "Failed to get map fd for map %s", xstr(XDP_SAMPLER_MAP_NAME));
		goto done;
	}

	perf_buffer = perf_buffer__new(map_fd, 8, handle_perf_event, NULL, (void *)sampler_ctx, NULL);

	res = libbpf_get_error(perf_buffer);
	if (res) {
		perror("perf_buffer__new failed");
		goto done;
	}

	while ((res = perf_buffer__poll(perf_buffer, 1000)) >= 0) {
		if (EXIT_FLAG)
			break;
	}

done:
	// The rest of the cleanup
	if (perf_buffer)
		perf_buffer__free(perf_buffer);
	if (ctx) {
		ecbpf_ctx__free(ctx);
	}
	pthread_exit(NULL);
}
