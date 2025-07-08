#ifndef _XDP_FILTER_MAPS_H
#define _XDP_FILTER_MAPS_H

#include <json-c/json.h> // libjson-c-dev
#include "xdp_filter.h"
#include "ip_chain.h"

struct filter_map_fds {
	int ip_src_fd;
	int ip6_src_fd;
	int config_fd;
	int state_fd;
};

int maps_open(struct filter_interface *interface);
int maps_clear(struct filter_interface *interface);
int maps_ip_chain_populate(struct filter_interface *interface, struct ip_chain* chain);
int maps_ip_chain_remove(struct filter_interface *interface, struct ip_chain* chain);
void maps_print(struct filter_interface *interface);
void maps_json(struct filter_interface *interface, struct json_object *root_obj);

#endif // _XDP_FILTER_MAPS_H
