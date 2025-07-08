#ifndef _xdp_sampler_stats_h
#define _xdp_sampler_stats_h

#include <net/if.h>
#include "configuration.h"
#define STATS_MAX_BACKOFF 600 // For failing statsd

struct stats_ctx;  // context is not exposed

struct stats_ctx* stats_new(char *interface, struct sampler_cfg *cfg);
void stats_free(struct stats_ctx *ctx);
void stats_start(struct stats_ctx *ctx);
void stats_stop(struct stats_ctx *ctx);
void stats_incr(struct stats_ctx *ctx);

#endif // _xdp_sampler_stats_h
