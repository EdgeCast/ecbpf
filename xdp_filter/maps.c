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
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <arpa/inet.h>

#include <json-c/json.h> // libjson-c-dev

#include "libecbpf.h"
#include "rootmaps.h"
#include "maps.h"

#define TIME_FORMAT "%a, %d %b %Y %T %z"

/* Internal methods */
int map_clear(int map_fd);

/*
 * Public functions
 */
int maps_clear(struct filter_interface *interface) {
	int err;

	err = maps_open(interface);
	if (err) {
		return 1;
	}

	printf("Clearing IPv4 trie for interface '%s'.\n", interface->name);
	map_clear(interface->fds->ip_src_fd);

	printf("Clearing IPv6 trie for interface '%s'.\n", interface->name);
	map_clear(interface->fds->ip6_src_fd);

	return 0;
}

int maps_open(struct filter_interface *interface) {
	int err = 0;
	struct filter_map_fds *fds = NULL;

	if (interface->fds)
		return 0;

	if (interface->ctx == NULL)
		errx(EX_SOFTWARE, "Interface ecbpf context not initialized for interface '%s'.", interface->name);

	fds = calloc(1, sizeof(struct filter_map_fds));

	fds->ip_src_fd = ecbpf__get_map_fd(interface->ctx, xstr(XDP_FILTER_IP_MAP));

	if (fds->ip_src_fd < 0) {
		err = -fds->ip_src_fd;
		fprintf(stderr, "Failed to get map fd for " xstr(XDP_FILTER_IP_MAP) "on interface '%s'.\n", interface->name);
		goto done;
	}

	fds->ip6_src_fd = ecbpf__get_map_fd(interface->ctx, xstr(XDP_FILTER_IP6_MAP));

	if (fds->ip6_src_fd < 0) {
		err = -fds->ip6_src_fd;
		fprintf(stderr, "Failed to get map fd for " xstr(XDP_FILTER_IP6_MAP) "on interface '%s'.\n", interface->name);
		goto done;
	}

	fds->config_fd = ecbpf__get_map_fd(interface->ctx, xstr(XDP_FILTER_CONFIG_MAP));

	if (fds->config_fd < 0) {
		err = -fds->config_fd;
		fprintf(stderr, "Failed to get map fd for " xstr(XDP_FILTER_CONFIG_MAP) "on interface '%s'.\n", interface->name);
		goto done;
	}

	fds->state_fd = ecbpf__get_map_fd(interface->ctx, xstr(XDP_FILTER_STATE_MAP));

	if (fds->state_fd < 0) {
		err = -fds->state_fd;
		fprintf(stderr, "Failed to get map fd for " xstr(XDP_FILTER_STATE_MAP) "on interface '%s'.\n", interface->name);
		goto done;
	}

done:
	if (err) {
		free(fds);
	} else {
		interface->fds = fds;
	}

	return err;
}

int maps_ip_chain_populate(struct filter_interface *interface, struct ip_chain* chain) {
	int err = 0;
	struct ip_chain *cur;
	char ip[INET6_ADDRSTRLEN];
	struct filter_drop_entry entry;

	err = maps_open(interface);
	if (err) {
		return err;
	}

	entry.load_time = time(NULL);
	cur = chain;
	do {
		// Setup the entry for this rule
		if (cur->tag) {
			strncpy(entry.tag, cur->tag, XDP_FILTER_NAME_LEN);
		} else {
			strncpy(entry.tag, "no tag", XDP_FILTER_NAME_LEN);
		}

		if (cur->af == AF_INET) {
			struct ip_trie_key ip_key = {
				.prefix_len = cur->prefix_len,
				.addr = cur->addr
			};
			err = bpf_map_update_elem(interface->fds->ip_src_fd, &ip_key, &entry, BPF_ANY);
		} else if (cur->af == AF_INET6) {
			struct ip6_trie_key ip_key = {
				.prefix_len = cur->prefix_len,
				.addr6 = cur->addr6
			};
			err = bpf_map_update_elem(interface->fds->ip6_src_fd, &ip_key, &entry, BPF_ANY);
		} else {
			errx(EX_SOFTWARE, "Unknown address family in ip address chain.");
		}

		if (err) {
			fprintf(stderr, "%s: bpf_map_update_elem failed with %m on interface '%s'.\n", __func__, interface->name);
			return 1;
		}

		cur = cur->next;
	} while (cur != NULL);

	return err;
}

int maps_ip_chain_remove(struct filter_interface *interface, struct ip_chain* chain) {
	struct ip_chain *cur;
	char ip[INET6_ADDRSTRLEN];
	int err;

	err = maps_open(interface);
	if (err) {
		return err;
	}

	cur = chain;
	do {
		if (cur->af == AF_INET) {
			struct ip_trie_key ip_key = {
				.prefix_len = cur->prefix_len,
				.addr = cur->addr
			};
			err = bpf_map_delete_elem(interface->fds->ip_src_fd, &ip_key);
		} else if (cur->af == AF_INET6) {
			struct ip6_trie_key ip_key = {
				.prefix_len = cur->prefix_len,
				.addr6 = cur->addr6
			};
			err = bpf_map_delete_elem(interface->fds->ip6_src_fd, &ip_key);
		} else {
			errx(EX_SOFTWARE, "Unknown address family in ip address chain.");
		}

		if (err < 0) {
			if (errno == ENOENT) {
				fprintf(stderr, "IP address %s not found in map for interface '%s'.\n",
						cur->address_string, interface->name);
			} else {
				fprintf(stderr, "Unknown error %m trying to delete ip %s for interface '%s'.\n",
						cur->address_string, interface->name);
			}
		}

		cur = cur->next;
	} while (cur != NULL);

	return err;
}

void maps_print(struct filter_interface *interface) {
	int err;
	struct ip_trie_key *prev = NULL;
	struct ip_trie_key cur;
	struct ip6_trie_key *prev6 = NULL;
	struct ip6_trie_key cur6;
	struct filter_drop_entry entry;
	struct tm *time;
	char ip[INET6_ADDRSTRLEN];
	char tbuf[128];

	err = maps_open(interface);
	if (err) {
		return;
	}

	printf("Drop Maps for interface '%s':\n\n", interface->name);

	// Walk IP map
	for (;;) {
		err = bpf_map_get_next_key(interface->fds->ip_src_fd, prev, &cur);
		if (err)
			break;

		err = bpf_map_lookup_elem(interface->fds->ip_src_fd, &cur, &entry);

		if (err)
			goto errx;

		if (inet_ntop(AF_INET, (void *) &(cur.addr), ip, INET6_ADDRSTRLEN) == NULL) {
			errx(EX_SOFTWARE, "Failed to print ip ptr...");
		}

		time = localtime(&entry.load_time);
		strftime(tbuf, sizeof(tbuf), TIME_FORMAT, time);

		printf("Address: %s/%d\tTag: %s\tLoad Time: %s\n", ip, cur.prefix_len, entry.tag, tbuf);

		prev = &cur;
	}

	// Walk IPv6 map
	for (;;) {
		err = bpf_map_get_next_key(interface->fds->ip6_src_fd, prev6, &cur6);
		if (err)
			break;

		err = bpf_map_lookup_elem(interface->fds->ip6_src_fd, &cur6, &entry);
		if (err)
			goto errx;

		if (inet_ntop(AF_INET6, (void *) &(cur6.addr6), ip, INET6_ADDRSTRLEN) == NULL) {
			errx(EX_SOFTWARE, "Failed to print ip ptr...");
		}

		time = localtime(&entry.load_time);
		strftime(tbuf, sizeof(tbuf), TIME_FORMAT, time);

		printf("Address: %s/%d\tName: %s\tLoad Time: %s\n", ip, cur6.prefix_len, entry.tag, tbuf);

		prev6 = &cur6;
	}

	printf("\n");
	return;
errx:
	errx(EX_SOFTWARE, "Failed to lookup or update element in IP map: %m for interface '%s'.", interface->name);
}

void maps_json(struct filter_interface *interface, struct json_object *root_obj) {
	int err;
	struct ip_trie_key *prev = NULL;
	struct ip_trie_key cur;
	struct ip6_trie_key *prev6 = NULL;
	struct ip6_trie_key cur6;
	struct filter_drop_entry entry;
	struct tm *time;
	char ip[INET6_ADDRSTRLEN];
	char tbuf[128];
	struct json_object *maps_obj, *drop_obj;

	err = maps_open(interface);
	if (err) {
		return;
	}

	maps_obj = json_object_new_array();
	json_object_object_add(root_obj, "source_drops", maps_obj);

	// Walk IP map
	for (;;) {
		err = bpf_map_get_next_key(interface->fds->ip_src_fd, prev, &cur);
		if (err)
			break;

		err = bpf_map_lookup_elem(interface->fds->ip_src_fd, &cur, &entry);

		if (err)
			goto errx;

		if (inet_ntop(AF_INET, (void *) &(cur.addr), ip, INET6_ADDRSTRLEN) == NULL) {
			errx(EX_SOFTWARE, "Failed to print ip ptr...");
		}

		drop_obj = json_object_new_object();
		time = localtime(&entry.load_time);
		strftime(tbuf, sizeof(tbuf), TIME_FORMAT, time);

		json_object_object_add(drop_obj, "Address", json_object_new_string(ip));
		json_object_object_add(drop_obj, "PrefixLen", json_object_new_int(cur.prefix_len));
		json_object_object_add(drop_obj, "Tag", json_object_new_string(entry.tag));
		json_object_object_add(drop_obj, "Load Time", json_object_new_string(tbuf));

		json_object_array_add(maps_obj, drop_obj);

		prev = &cur;
	}

	// Walk IPv6 map
	for (;;) {
		err = bpf_map_get_next_key(interface->fds->ip6_src_fd, prev6, &cur6);
		if (err)
			break;

		err = bpf_map_lookup_elem(interface->fds->ip6_src_fd, &cur6, &entry);
		if (err)
			goto errx;

		if (inet_ntop(AF_INET6, (void *) &(cur6.addr6), ip, INET6_ADDRSTRLEN) == NULL) {
			errx(EX_SOFTWARE, "Failed to print ip ptr...");
		}

		drop_obj = json_object_new_object();

		time = localtime(&entry.load_time);
		strftime(tbuf, sizeof(tbuf), TIME_FORMAT, time);

		json_object_object_add(drop_obj, "Address", json_object_new_string(ip));
		json_object_object_add(drop_obj, "PrefixLen", json_object_new_int(cur6.prefix_len));
		json_object_object_add(drop_obj, "Tag", json_object_new_string(entry.tag));
		json_object_object_add(drop_obj, "Load Time", json_object_new_string(tbuf));

		json_object_array_add(maps_obj, drop_obj);

		prev6 = &cur6;
	}

	return;
errx:
	errx(EX_SOFTWARE, "Failed to lookup or update element in IP map: %m");
}

/* 
 * "Private" functions
 */
int map_clear(int map_fd) {
	void *key = NULL;
	void *prev_key = NULL;
	int err = 0;
	struct bpf_map_info info = {}; // info must be zeroed out for bpf_obj_get_info_by_fd
	uint32_t len = sizeof(info);

	err = bpf_obj_get_info_by_fd(map_fd, &info, &len);
	if (err) {
		fprintf(stderr, "Failed to get map info\n");
		return err;
	}

	key = malloc(info.key_size);

	while (true) {
		err = bpf_map_get_next_key(map_fd, NULL, key);
		if (err < 0) {
			if (errno == ENOENT) {
				err = 0; // Behavior for last key
			} else {
				fprintf(stderr, "Failed to bpf_map_get_next_key: %m\n");
			}
			break;
		}

		err = bpf_map_delete_elem(map_fd, key);
		if (err < 0) {
			fprintf(stderr, "Failed to delete key: %m\n");
			break;
		}
	}

	free(key);

	return err;
}

