#define _GNU_SOURCE
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
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <arpa/inet.h>

#include "maps.h"
#include "stats.h"

volatile sig_atomic_t statsd_failure_flag = false;

struct stats_statsd_ctx {
	char *host;
	char *port;
	int failures;
};

struct filter_state* filter_state_get(struct filter_interface *interface) {
	int idx = 0;
	int err;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct filter_state *states;
	struct filter_state *sum;

	err = maps_open(interface);
	if (err) {
		return NULL;
	}

	states = calloc(nr_cpus, sizeof(struct filter_state));
	sum = calloc(1, sizeof(struct filter_state));

	err = bpf_map_lookup_elem(interface->fds->state_fd, &idx, states);
	if (err) {
		errx(EX_SOFTWARE, "Failed to lookup stats: %m");
	}

	for (int i = 0; i < nr_cpus; i++) {
		sum->eth_frame_err += states[i].eth_frame_err;
		sum->ip_header_err += states[i].ip_header_err;
		sum->ip6_header_err += states[i].ip6_header_err;
		sum->ip_drop_count += states[i].ip_drop_count;
		sum->ip6_drop_count += states[i].ip6_drop_count;
		sum->ip_frag_drop_count += states[i].ip_frag_drop_count;
		sum->ptb_sent_count += states[i].ptb_sent_count;
		sum->ptb_err_count += states[i].ptb_err_count;
		sum->ptb_mem_err_count += states[i].ptb_mem_err_count;
	}

	free(states);
	return sum;
}

void filter_state_free(struct filter_state *state) {
	free(state);
}

void stats_print(struct filter_interface *interface) {
	int err;
	struct filter_state *state;

	state = filter_state_get(interface);
	if (state == NULL) {
		return;
	}

	printf("Stats for interface '%s':\n\n", interface->name);
	printf("eth_frame_err: %lu\n", state->eth_frame_err);
	printf("ip_header_err: %lu\n", state->ip_header_err);
	printf("ip6_header_err: %lu\n", state->ip6_header_err);
	printf("ip_drop_count: %lu\n", state->ip_drop_count);
	printf("ip6_drop_count: %lu\n", state->ip6_drop_count);
	printf("ip_frag_drop_count: %lu\n", state->ip_frag_drop_count);
	printf("ptb_sent_count: %lu\n", state->ptb_sent_count);
	printf("ptb_err_count: %lu\n", state->ptb_err_count);
	printf("ptb_mem_err_count: %lu\n", state->ptb_mem_err_count);

	filter_state_free(state);
}

void stats_statsd_alarm(int sig) {
	statsd_failure_flag = false;
}

void stats_statsd_submit_metric(struct stats_statsd_ctx* ctx, char *ifname, char *name, uint64_t count) {
	int err = 0;
	int backoff;
	char *metric;

	if (statsd_failure_flag) {
		//fprintf(stderr, "xdp_filter: statsd_failure_flag set\n");
		return;
	}

	err = asprintf(&metric, "filter.%s@%s", name, ifname);
	if (err < 0) {
		errx(EXIT_FAILURE, "xdp_filter: Failed to allocate statsd namespace string");
	}

	err = ecbpf_log_statsd_gauge(ctx->host, ctx->port, metric, count);
	if (err) {
		statsd_failure_flag = true; // Set the failure flag
		if ((1 << ctx->failures) < LIBECBPF_STATSD_MAX_BACKOFF) {
			backoff = 1 << ctx->failures;
			ctx->failures++;
		} else {
			backoff = LIBECBPF_STATSD_MAX_BACKOFF;
		}
		fprintf(stderr, "xdp_filter: ecbpf_log_statsd_counter call failed (%i): Turning off stats for %i seconds\n", err, backoff);
		/* Rather than sleeping here, we just set an alarm.  This is so that when we
		 * reconnect, we don't potentially send stale stats since many calls to stats_statsd_submit_metric
		 * are made at once.
		 */
		alarm(backoff);
	} else {
		ctx->failures = 0;
	}

	free(metric);
}

struct stats_statsd_ctx* stats_statsd_ctx_new(char *host, char *port) {
	struct stats_statsd_ctx *ctx;
	struct sigaction sig_act;

	ctx = malloc(sizeof(struct stats_statsd_ctx));
	if (ctx == NULL) {
		errx(EX_SOFTWARE, "Failed to allocate memory");
	}
	ctx->failures = 0;
	ctx->host = strdup(host);
	ctx->port = strdup(port);

	/* Setup signal handler */
	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;
	sig_act.sa_handler = stats_statsd_alarm;
	sigaction(SIGALRM, &sig_act, NULL);

	return ctx;
}

void stats_statsd_ctx_free(struct stats_statsd_ctx* ctx) {
	if (ctx == NULL)
		return;

	free(ctx->host);
	free(ctx->port);
	free(ctx);
}

void stats_statsd(struct stats_statsd_ctx* ctx, struct filter_interface *interface) {
	int err;
	char *metric;
	struct filter_state *state;
	struct filter_state sum = {};

	state = filter_state_get(interface);
	if (state == NULL) {
		errx(EX_SOFTWARE, "xdp_filter: stats_statsd: call to filter_state_get failed");
	}

	stats_statsd_submit_metric(ctx, interface->name, "eth_frame_err", state->eth_frame_err);
	stats_statsd_submit_metric(ctx, interface->name, "ip_header_err", state->ip_header_err);
	stats_statsd_submit_metric(ctx, interface->name, "ip6_header_err", state->ip6_header_err);
	stats_statsd_submit_metric(ctx, interface->name, "ip_drop_count", state->ip_drop_count);
	stats_statsd_submit_metric(ctx, interface->name, "ip6_drop_count", state->ip6_drop_count);
	stats_statsd_submit_metric(ctx, interface->name, "ip_frag_drop_count", state->ip_frag_drop_count);
	stats_statsd_submit_metric(ctx, interface->name, "ptb_sent_count", state->ptb_sent_count);
	stats_statsd_submit_metric(ctx, interface->name, "ptb_err_count", state->ptb_err_count);
	stats_statsd_submit_metric(ctx, interface->name, "ptb_mem_err_count", state->ptb_mem_err_count);

	filter_state_free(state);
}

void stats_json(struct filter_interface *interface, struct json_object *root_obj) {
	int err;
	struct json_object *stats_obj;
	struct filter_state *state;

	state = filter_state_get(interface);
	if (state == NULL) {
		return;
	}

	stats_obj = json_object_new_object();
	json_object_object_add(root_obj, "stats", stats_obj);

	json_object_object_add(stats_obj, "eth_frame_err", json_object_new_int64(state->eth_frame_err));
	json_object_object_add(stats_obj, "ip_header_err", json_object_new_int64(state->ip_header_err));
	json_object_object_add(stats_obj, "ip6_header_err", json_object_new_int64(state->ip6_header_err));
	json_object_object_add(stats_obj, "ip_drop_count", json_object_new_int64(state->ip_drop_count));
	json_object_object_add(stats_obj, "ip6_drop_count", json_object_new_int64(state->ip6_drop_count));
	json_object_object_add(stats_obj, "ip_frag_drop_count", json_object_new_int64(state->ip_frag_drop_count));
	json_object_object_add(stats_obj, "ptb_sent_count", json_object_new_int64(state->ptb_sent_count));
	json_object_object_add(stats_obj, "ptb_err_count", json_object_new_int64(state->ptb_err_count));
	json_object_object_add(stats_obj, "ptb_mem_err_count", json_object_new_int64(state->ptb_mem_err_count));

	filter_state_free(state);
}

int stats_clear(struct filter_interface *interface) {
	int idx = 0;
	int err = 0;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct filter_state **states;

	err = maps_open(interface);
	if (err) {
		return err;
	}

	states = calloc(nr_cpus, sizeof(struct filter_state));

	err = bpf_map_update_elem(interface->fds->state_fd, &idx, states, BPF_ANY);

	if (err) {
		errx(EX_SOFTWARE, "Failed to lookup stats: %m");
	}

	free(states);

	return err;
}
