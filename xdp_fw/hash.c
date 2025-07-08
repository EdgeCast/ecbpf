/*
 * Routines for hashing pcap packets
 */
#include <stdio.h>
#include <stdlib.h>
#include "hash.h"

struct hasher* hasher_new() {
	struct hasher* ctx;

	ctx = malloc(sizeof(struct hasher));

	if (ctx == NULL) {
		fprintf(stderr, "Failed to malloc: %m\n");
		return NULL;
	}

	ctx->mdctx = EVP_MD_CTX_create();
	if (ctx->mdctx == NULL) {
		fprintf(stderr, "Failed to create openssl message digest.\n");
		free(ctx);
		return NULL;
	}

	return ctx;
}

void hasher_free(struct hasher *h) {
	EVP_MD_CTX_destroy(h->mdctx);
	free(h);
}

int hasher_pkt(struct hasher *h, const struct pcap_pkthdr *ph, const u_char *bytes) {
	int res;

	res = EVP_DigestInit_ex(h->mdctx, EVP_sha1(), NULL);
	if (res != 1) {
		fprintf(stderr, "Failed to initialize openssl message digest.\n");
		return -1;
	}

	res = EVP_DigestUpdate(h->mdctx, bytes, ph->caplen);
	if (res != 1) {
		fprintf(stderr, "Failed to hash packet.\n");
		return -1;
	}

	res = EVP_DigestFinal_ex(h->mdctx, h->digest, &h->md_len);

	if (res != 1) {
		fprintf(stderr, "Failed to finalize packet hash.\n");
		return -1;
	}

	for (int i = 0; i < h->md_len; i++) {
		sprintf(h->md_str + (2 * i), "%02x", h->digest[i]);
	}

	return 0;
}