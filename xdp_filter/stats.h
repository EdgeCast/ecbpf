#ifndef _XDP_FILTER_STATS_H
#define _XDP_FILTER_STATS_H

#include <json-c/json.h> // libjson-c-dev
#include "xdp_filter.h"

void stats_print(struct filter_interface *interface);
void stats_json(struct filter_interface *interface, struct json_object *root_obj);
struct stats_statsd_ctx;
struct stats_statsd_ctx* stats_statsd_ctx_new(char *host, char *port);
void stats_statsd_ctx_free(struct stats_statsd_ctx*);
void stats_statsd(struct stats_statsd_ctx* ctx, struct filter_interface *interface);
int stats_clear(struct filter_interface *interface);

#endif // _XDP_FILTER_STATS_H
