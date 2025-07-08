#ifndef _hash_h
#define _hash_h

#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <openssl/evp.h>

// So we can reuse the openssl digest conext
struct hasher {
	EVP_MD_CTX *mdctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	char md_str[EVP_MAX_MD_SIZE * 2 + 1];
	unsigned int md_len;
};

struct hasher* hasher_new();
void hasher_free(struct hasher *);
int hasher_pkt(struct hasher *, const struct pcap_pkthdr *, const u_char *);

#endif // _hash_h
