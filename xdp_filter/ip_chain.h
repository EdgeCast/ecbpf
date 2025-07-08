#ifndef _XDP_FILTER_IP_CHAIN_H
#define _XDP_FILTER_IP_CHAIN_H

#include <stdint.h>
#include <arpa/inet.h>

struct ip_chain {
	struct ip_chain *next;
	char *address_string;
	char *tag; 
	int af;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
	uint8_t prefix_len;
};

void ip_chain_free(struct ip_chain* chain);
void ip_chain_add(struct ip_chain** chain, char* address_string);
void ip_chain_tag(struct ip_chain *head, char *tag_list);
void ip_chain_print(struct ip_chain* chain);

#endif // _XDP_FILTER_IP_CHAIN_H
