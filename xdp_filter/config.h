#ifndef _XDP_FILTER_CONFIG_H
#define _XDP_FILTER_CONFIG_H

#include <json-c/json.h> // libjson-c-dev
#include "xdp_filter.h"

int config_init(struct filter_interface *interface);
int config_ptb_max_pps_set(struct filter_interface *interface, int ptb_max_pps);
int config_frags_drop_set(struct filter_interface *interface, int frags_drop);
void config_print(struct filter_interface *interface);
void config_json(struct filter_interface *interface, struct json_object *root_obj);

#endif // _XDP_FILTER_CONFIG_H
