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

#include "ip_chain.h"

void ip_chain_add(struct ip_chain** chain, char* address_string) {
	struct ip_chain *new;
	struct ip_chain *cur;
	unsigned char buf[sizeof(struct in6_addr)];
	char *c;
	bool default_prefix = false;
	int prefix_len = 128;
	int res;

	// Add address in
	new = calloc(1, sizeof(struct ip_chain));

	if (new == NULL) {
		errx(EX_SOFTWARE, "Failed to allocate memory for ip_chain");
	}

	// Save the address string before we split it
	new->address_string = strdup(address_string);

	// Check for prefix
	c = strchr(address_string, '/');
	if (c == NULL) {
		default_prefix = true;
	} else {
		*c = '\0';
		prefix_len = atoi(++c);
		if (prefix_len < 8) {
			errx(EX_USAGE, "Prefix too short (must be at least 8): %s", address_string);
		}
	}

	// Parse the IP address
	res = inet_pton(AF_INET, address_string, buf);

	if (res == 0) { /* wrong address family */
		res = inet_pton(AF_INET6, address_string, buf);
		if (res != 1) {
			errx(EX_USAGE, "Recognized address family, but not IP or IP6: %s", address_string);
		}

		if (prefix_len > 128) {
			errx(EX_USAGE, "Invalid prefix length %d for address %s", prefix_len, address_string);
		}

		new->af = AF_INET6;
		new->prefix_len = prefix_len;
		new->addr6 = *(struct in6_addr *)buf;

	} else if (res == 1) {
		if (prefix_len > 32) {
			errx(EX_USAGE, "Invalid prefix length %d for address %s", prefix_len, address_string);
		}

		new->af = AF_INET;
		new->prefix_len = prefix_len;
		new->addr6 = *(struct in6_addr *)buf;
	} else {
		errx(EX_USAGE, "Invalid address: %s", address_string);
	}

	// Make head or append at end of chain
	if (*chain == NULL) {
		*chain=new;
	} else {
		cur = *chain;
		while (cur->next != NULL) { // slow, I know...
			cur = cur->next;
		}
		cur->next = new;
	}
}

void ip_chain_tag(struct ip_chain *head, char *tag_list) {
	char *tok;
	char *stringp = tag_list;
	struct ip_chain *cur = head;

	while ((tok = strsep(&stringp, ",;")) != NULL) {
		if (cur == NULL) {
			printf("Warning: ran out of IP addresses before tags\n");
			return;
		}

		cur->tag = strdup(tok);
		printf("Adding tag \"%s\" to address %s\n", cur->tag, cur->address_string);
		cur = cur->next;
	}
}

void ip_chain_free(struct ip_chain* chain) {
	struct ip_chain *cur;

	if (chain == NULL)
		return;

	do {
		cur = chain->next;
		if (chain->tag)
			free(chain->tag);
		if (chain->address_string)
			free(chain->address_string);
		free(chain);
		chain = cur;
	} while (cur != NULL);
}

void ip_chain_print(struct ip_chain* chain) {
	struct ip_chain *cur;
	char ip[INET6_ADDRSTRLEN];

	printf("Address chain:\n");
	if (chain == NULL) {
		printf("No entries in chain\n");
		return;
	}

	cur = chain;
	do {
	   	if (inet_ntop(cur->af, (void *) &(cur->addr), ip, INET6_ADDRSTRLEN) == NULL) {
			errx(EX_SOFTWARE, "Failed to print ip cur...");
		}
		printf("Address String: %s Address: %s/%d Tag: %s\n",
				cur->address_string, ip, cur->prefix_len, cur->tag);
		cur = cur->next;
	} while (cur != NULL);
}

