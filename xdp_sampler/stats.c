#define _GNU_SOURCE // asprintf, pthread_setname_np
#include <err.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include "libecbpf.h"

#include "stats.h"
#include "xdp_sampler.h"

// Internal conext details are to be managed via functions
struct stats {
	_Atomic int count; // current packets received
	int count_last_sec; // packets received in last window
	int rev; // revision for pthread condition predicate
	bool no_more_stats;
};

struct stats_thread {
	bool has_tid;
	pthread_t tid;
	char name[16];
};

struct stats_ctx {
	// configuration
	char statsd_host[254]; // https://devblogs.microsoft.com/oldnewthing/?p=7873
	char statsd_port[16]; // https://tools.ietf.org/html/rfc6335#section-5.1
	char interface[IFNAMSIZ];
	bool debug; // run debug print thread
	bool statsd_enable; // submit to statsd

	// the pearl
	struct stats stats;

	// threads
	int thread_count;
	pthread_mutex_t thread_lock;
	struct stats_thread stats_thread;
	struct stats_thread debug_thread;
	struct stats_thread statsd_thread;

	// stats globals that shouldn't be global
	pthread_mutex_t stats_lock;
	pthread_cond_t  stats_cond;
};

// threads, local to stats.c
void *stats_thread(void *data);
void *stats_debug_thread(void *data);
void *statsd_thread(void *data);
// internal functions
bool stats_stopped(struct stats_ctx *ctx);

struct stats_ctx* stats_new(char *interface, struct sampler_cfg *cfg) {
	struct stats_ctx *ctx = calloc(1, sizeof(struct stats_ctx));
	if (ctx == NULL)
		errx(EXIT_FAILURE, "Failed to allocate memory in stats_new");

	// Setup configuration
	strncpy(ctx->interface, interface, sizeof(ctx->interface)-1);
	strncpy(ctx->statsd_host, cfg->statsd_host, sizeof(ctx->statsd_host)-1);
	strncpy(ctx->statsd_port, cfg->statsd_port, sizeof(ctx->statsd_port)-1);
	ctx->debug = cfg->debug;
	ctx->statsd_enable = cfg->statsd_enable;

	// Setup stats
	if (pthread_mutex_init(&ctx->stats_lock, NULL) != 0) {
        fprintf(stderr, "Failed to init stats mutex: %m\n");
		free(ctx);
		return NULL;
	}

	if (pthread_cond_init(&ctx->stats_cond, NULL) != 0) {
        fprintf(stderr, "Failed to init stats cond: %m\n");
		free(ctx);
		return NULL;
	}

	// Already zero, but in case we change the code...
	atomic_init(&(ctx->stats.count), 0);
	ctx->stats.count_last_sec = 0;
	ctx->stats.no_more_stats = false;

	// threads
	if (pthread_mutex_init(&ctx->thread_lock, NULL) != 0) {
        fprintf(stderr, "Failed to init stats thread mutex: %m\n");
		free(ctx);
		return NULL;
	}

	ctx->thread_count = 0;
	ctx->stats_thread.has_tid = false;
	strncpy(ctx->stats_thread.name, "stats", sizeof(ctx->stats_thread.name));

	ctx->statsd_thread.has_tid = false;
	strncpy(ctx->statsd_thread.name, "statsd", sizeof(ctx->statsd_thread.name));

	ctx->debug_thread.has_tid = false;
	strncpy(ctx->debug_thread.name, "stats_debug", sizeof(ctx->debug_thread.name));

	return ctx;
}

void stats_free(struct stats_ctx *ctx) {
	if (!stats_stopped(ctx))
		errx(EXIT_FAILURE, "Attempt to free stats context with threads running");

	free(ctx);
}

void stats_start(struct stats_ctx *ctx) {
	int res;

	pthread_mutex_lock(&ctx->thread_lock);

	/* Start stats windowing thread */
	res = pthread_create(&ctx->stats_thread.tid, NULL, stats_thread, (void*)ctx);
	if (res) {
		errx(EXIT_FAILURE, "Failed to start stats thread: %s", strerror(res));
	}
	ctx->stats_thread.has_tid = true;
	ctx->thread_count++;

	/* Set stats windowing thread name */
	res = pthread_setname_np(ctx->stats_thread.tid, ctx->stats_thread.name);
	if (res) {
		errx(EXIT_FAILURE, "Failed to set stats thread name: %s", strerror(res));
	}

	/* Start stats debug thread */
	if (ctx->debug) {
		res = pthread_create(&ctx->debug_thread.tid, NULL, stats_debug_thread, (void*)ctx);
		if (res) {
			errx(EXIT_FAILURE, "Failed to start stats debug print thread: %s", strerror(res));
		}
		ctx->debug_thread.has_tid = true;
		ctx->thread_count++;

		res = pthread_setname_np(ctx->debug_thread.tid, ctx->debug_thread.name);
		if (res) {
			err(EXIT_FAILURE, "Failed to set stats debug print thread name: %s", strerror(res));
		}
	}

	if (ctx->statsd_enable) {
		res = pthread_create(&ctx->statsd_thread.tid, NULL, statsd_thread, (void*)ctx);
		if(res) {
			errx(EXIT_FAILURE, "Failed to start statsd thread thread: %s", strerror(res));
		}
		ctx->statsd_thread.has_tid = true;
		ctx->thread_count++;

		res = pthread_setname_np(ctx->statsd_thread.tid, ctx->statsd_thread.name);
		if (res) {
			errx(EXIT_FAILURE, "Failed to set stats statsd thread name: %s", strerror(res));
		}
	}

	pthread_mutex_unlock(&ctx->thread_lock);
}

// Just to hide the context
void stats_incr(struct stats_ctx *ctx) {
	// Atomic variable
	ctx->stats.count++;
}

// helper for stopping threads called by stats_stop
static void thread_join(struct stats_ctx *ctx, struct stats_thread *thread) {
	int res;

	if (!thread->has_tid)
		return;

	// We can't use pthread_getname_np(tid, tbuf, sizeof tbuf)
	// since we can't get the name of a dead thread.
	printf("Waiting for thread %s to exit\n", thread->name);
	res = pthread_join(thread->tid, NULL);
	if (res) {
		errx(EXIT_FAILURE, "Joining thread %s failed: %m\n", thread->name);
	}

	thread->has_tid = false;
	// Protected by mutex ctx->thread_lock in stats_stop
	ctx->thread_count--;
}

void stats_stop(struct stats_ctx *ctx) {
	if (stats_stopped(ctx))
		return;

	// Signal the threads to stop
	pthread_mutex_lock(&ctx->stats_lock);
	ctx->stats.no_more_stats = true;
	pthread_cond_broadcast(&ctx->stats_cond);
	pthread_mutex_unlock(&ctx->stats_lock);

	// Join the threads
	pthread_mutex_lock(&ctx->thread_lock);
	thread_join(ctx, &ctx->debug_thread);
	thread_join(ctx, &ctx->stats_thread);
	thread_join(ctx, &ctx->statsd_thread);
	pthread_mutex_unlock(&ctx->thread_lock);
}

// See if all threads have stopped
bool stats_stopped(struct stats_ctx *ctx) {
	if (ctx->thread_count == 0) {
		return true;
	} else if (ctx->thread_count < 0) {
		errx(EXIT_FAILURE, "Thread count underflow: %i", ctx->thread_count);
	}

	return false;
}

struct stats stats_get(struct stats_ctx *ctx, int rev) {
	struct stats res;

	pthread_mutex_lock(&ctx->stats_lock);
	// Wait for a new revision of stats
	while (ctx->stats.rev == rev && !ctx->stats.no_more_stats)
		pthread_cond_wait(&ctx->stats_cond, &ctx->stats_lock);

	res = ctx->stats;

	pthread_mutex_unlock(&ctx->stats_lock);

	return res;
}

// Threads
void *stats_thread(void *data) {
	struct stats_ctx *ctx = (struct stats_ctx *) data;
	bool no_more_stats;

	for (;;) {
		pthread_mutex_lock(&ctx->stats_lock);

		// Exit thread if no more stats flag is set
		if (ctx->stats.no_more_stats) {
			printf("stats_thread (%s): no_more_stats: exiting\n", ctx->interface);
			pthread_mutex_unlock(&ctx->stats_lock);
			break;
		}

		ctx->stats.count_last_sec = atomic_exchange(&(ctx->stats.count), 0);
		ctx->stats.rev++;
		pthread_cond_broadcast(&ctx->stats_cond);
		pthread_mutex_unlock(&ctx->stats_lock);
		sleep(1); // statsd assumption...
	}

	pthread_exit(NULL);
}

void *stats_debug_thread(void *data) {
	struct stats_ctx *ctx = (struct stats_ctx *) data;
	struct stats win;
	win.rev = -1;
	printf("stats_debug_thread: Starting\n");

	for (;;) {
		win = stats_get(ctx, win.rev);
		printf("stats_debug_thread (%s): rev %i count %i count_last_sec %i\n", ctx->interface, win.rev, win.count, win.count_last_sec);
		if (win.no_more_stats) {
			printf("stats_debug_thread (%s): no_more_stats: exiting\n", ctx->interface);
			break;
		}
	}

	pthread_exit(NULL);
}

void *statsd_thread(void *data) {
	struct stats_ctx *ctx = (struct stats_ctx *) data;
	int res, failures = 0, backoff;
	struct stats win;
	int last_rev;
	char *metric;

	printf("statsd_thread (%s): Starting\n", ctx->interface);

	res = asprintf(&metric, "sampler.samples@%s", ctx->interface);
	if (res < 0) {
		err(EXIT_FAILURE, "statsd_thread (%s): Failed to allocate namespace string", ctx->interface);
	}

	// Start init so we can complain about rev delta > 1
	win = stats_get(ctx, -1);

	for (;;) {
		last_rev = win.rev;
		win = stats_get(ctx, last_rev);
		if (win.no_more_stats) {
			printf("statsd_thread (%s): no_more_stats: exiting\n", ctx->interface);
			break;
		}

		if (win.rev != ++last_rev)
			fprintf(stderr, "statsd_thread (%s): Dropped stats, delta between revs: %i\n", ctx->interface, win.rev - last_rev);

		res = ecbpf_log_statsd_counter(ctx->statsd_host, ctx->statsd_port, metric, win.count_last_sec);
		if (res) {
			if ((1 << failures) < LIBECBPF_STATSD_MAX_BACKOFF) {
				backoff = 1 << failures;
				failures++;
			} else {
				backoff = LIBECBPF_STATSD_MAX_BACKOFF;
			}
			fprintf(stderr, "statsd_thread (%s): statsd_counter call failed: %i: Sleeping for %i seconds\n", ctx->interface, res, backoff);
			sleep(backoff);
		} else {
			failures = 0;
		}
	}

	free(metric);
	pthread_exit(NULL);
}
