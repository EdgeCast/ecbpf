#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <unistd.h>

#include "libecbpf.h"
#include "xdp_fw.h"
#include "rootmaps.h"
#include "cfg.h"
#include "rules.h"
#include "test.h"
#include "hash.h"

// For passing conext to pcap function
struct pcap_context {
	int prog_fd;
	int runs;
	FILE* log;
	struct hasher *hasher;
	struct fw_cfg *config;
};

void my_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/*
 * Test struct routines
 */
struct test *test_new(unsigned char *sha1, enum xdp_action act) {
	struct test *new = calloc(1, sizeof(struct test));

	memcpy(new->sha1, sha1, SHA1_SIZE);
	new->act = act;

	return new;
}

void test_free(struct test *test) {
	free(test);
}

struct test *test_lookup(struct hasher* h, struct fw_cfg *config) {
	unsigned char idx = h->digest[0];
	struct test *cur = config->tests[idx];

	while (cur != NULL) {
		if (memcmp(cur->sha1, h->digest, SHA1_SIZE) == 0) {
			return cur;
		}

		cur = cur->next;
	}

	return NULL;
}

/*
 * Test printing functions
 */
char *xdp_ret_to_str(int ret) {
	switch(ret) {
		case XDP_ABORTED:
			return "XDP_ABORTED";
		case XDP_DROP:
			return "XDP_DROP";
		case XDP_PASS:
			return "XDP_PASS";
		case XDP_TX:
			return "XDP_TX";
		case XDP_REDIRECT:
			return "XDP_REDIRECT";
	}
	return "UNKNOWN";
}

void test_print(struct test *test) {
	printf("test sha1 ");

	for(int i = 0; i < SHA1_SIZE; i++)
		printf("%02x", test->sha1[i]);

	printf(" xdp_action %s\n", xdp_ret_to_str(test->act));
}

/*
 * Packet printing functions
 */
void print_pkt_tcp(void *capend, const u_char *bytes) {
	struct tcphdr *tcph = (struct tcphdr*) bytes;

	if ((void *)(tcph + 1) > capend) {
		printf("Packet shorter than struct tcphdr\n");
		return;
	}

	printf("sport %i -> dport %i window %i",
			ntohs(tcph->source),
			ntohs(tcph->dest),
			ntohs(tcph->window));

	printf(" flags (");

	if (tcph->cwr)
		printf(" cwr");
	if (tcph->ece)
		printf(" ece");
	if (tcph->urg)
		printf(" urg");
	if (tcph->ack)
		printf(" ack");
	if (tcph->psh)
		printf(" psh");
	if (tcph->rst)
		printf(" rst");
	if (tcph->syn)
		printf(" syn");
	if (tcph->fin)
		printf(" fin");

	printf(" )");
}

void print_pkt_udp(void *capend, const u_char *bytes) {
	struct udphdr *udph = (struct udphdr*) bytes;

	if ((void *)(udph + 1) > capend) {
		printf("Packet shorter than struct udphdr\n");
		return;
	}

	printf("sport %i -> dport %i",
			ntohs(udph->source),
			ntohs(udph->dest));
}

void print_pkt_icmp(void *capend, const u_char *bytes) {
	struct icmphdr *icmph = (struct icmphdr*) bytes;

	if ((void *)(icmph + 1) > capend) {
		printf("Packet shorter than struct icmphdr\n");
		return;
	}

	printf("type %i code %i",
			icmph->type,
			icmph->code);
}

void print_pkt_icmp6(void *capend, const u_char *bytes) {
	struct icmp6hdr *icmph = (struct icmp6hdr*) bytes;

	if ((void *)(icmph + 1) > capend) {
		printf("Packet shorter than struct icmp6hdr\n");
		return;
	}

	printf("type %i code %i",
			icmph->icmp6_type,
			icmph->icmp6_code);
}

void print_pkt_ip(void *capend, const u_char *bytes) {
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	struct iphdr *iph = (struct iphdr*) bytes;

	if ((void *)(iph + 1) > capend) {
		printf("Packet shorter than struct iphdr\n");
		return;
	}

	inet_ntop(AF_INET, &(iph->saddr), src, sizeof(src));
	inet_ntop(AF_INET, &(iph->daddr), dst, sizeof(dst));

	printf("IPv4 Src %s -> Dst %s ttl %i", src, dst, iph->ttl);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		printf(" proto tcp ");
		print_pkt_tcp(capend, (const u_char*) (iph + 1));
		break;
	case IPPROTO_UDP:
		printf(" proto udp ");
		print_pkt_udp(capend, (const u_char*) (iph + 1));
		break;
	case IPPROTO_ICMP:
		printf(" proto icmp ");
		print_pkt_icmp(capend, (const u_char*) (iph + 1));
		break;
	};

	printf("\n");

}

void print_pkt_ip6(void *capend, const u_char *bytes) {
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	struct ipv6hdr *iph = (struct ipv6hdr*) bytes;

	if ((void *)(iph + 1) > capend) {
		printf("Packet shorter than struct ipv6hdr\n");
		return;
	}

	inet_ntop(AF_INET6, &(iph->saddr), src, sizeof(src));
	inet_ntop(AF_INET6, &(iph->daddr), dst, sizeof(dst));

	printf("IPv6 Src %s -> Dst %s ttl %i", src, dst, iph->hop_limit);

	switch (iph->nexthdr) {
	case IPPROTO_TCP:
		printf(" proto tcp ");
		print_pkt_tcp(capend, (const u_char*) (iph + 1));
		break;
	case IPPROTO_UDP:
		printf(" proto udp ");
		print_pkt_udp(capend, (const u_char*) (iph + 1));
		break;
	case IPPROTO_ICMPV6:
		printf(" proto icmp6 ");
		print_pkt_icmp6(capend, (const u_char*) (iph + 1));
		break;
	};

	printf("\n");
}

void print_pkt(const struct pcap_pkthdr *h, const u_char *bytes) {
	struct ethhdr *eth = (struct ethhdr*) bytes;
	void *capend = (void *)bytes + h->caplen - 1;

	if ((void *)(eth + 1) > capend) {
		printf("Packet shorter than struct ethhdr\n");
		return;
	}

	printf("Len %02i ", h->caplen);

	switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			print_pkt_ip(capend, (const u_char*) (eth + 1));
			break;
		case ETH_P_IPV6:
			print_pkt_ip6(capend, (const u_char*) (eth + 1));
			break;
		case ETH_P_8021Q:
			printf("802.1q packet, not supported\n");
			break;
	}
}

void my_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	char buf[4096];
	int err;
	double average = 0;
	struct pcap_context *pctx = (struct pcap_context *) user;
	uint32_t min = UINT32_MAX, max = 0;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.repeat = 1,
		.data_in = bytes,
		.data_size_in = h->caplen,
		.data_out = buf,
		.data_size_out = sizeof(buf),
	);


	for (int i = 0; i < pctx->runs; i++) {
		err = bpf_prog_test_run_opts(pctx->prog_fd, &topts);

		if(err) {
			errx(EX_SOFTWARE, "Program test run returned failure (%i): %m", err);
		}

		average += (1.0/pctx->runs) * topts.duration;
		if (topts.duration > max)
			max = topts.duration;
		if (topts.duration < min)
			min = topts.duration;
	}

	err = hasher_pkt(pctx->hasher, h, bytes);
	if (err != 0) {
		errx(EX_SOFTWARE, "Failed to hash packet");
	}

	print_pkt(h, bytes);

	printf(" test sha1 %s xdp_action %s\n",
		pctx->hasher->md_str,
		xdp_ret_to_str(topts.retval));
	// Use tcpdump -tt to get the same time stamp
	printf(" pkt ts: %li.%li caplen: %i average: %f ns min: %i max: %i\n",
		h->ts.tv_sec,
		h->ts.tv_usec,
		h->caplen,
		average,
		min,
		max);

	if (pctx->log)
		fprintf(pctx->log, "%s,%s,%s,%i,%f,%i\n",
				pctx->config->filename,
				pctx->hasher->md_str,
				xdp_ret_to_str(topts.retval),
				min, average, max);

	struct test *test = test_lookup(pctx->hasher, pctx->config);

	if (test != NULL) {
		if(test->act != topts.retval) {
			printf(" test fail\n");
			fprintf(stderr, "test failure: expected %s, got %s for hash %s\n",
					xdp_ret_to_str(test->act),
					xdp_ret_to_str(topts.retval),
					pctx->hasher->md_str);
			errx(EX_SOFTWARE, "exiting...");
		} else {
			printf(" test pass\n");
		}
	}

	printf("\n");
}

void test(char *program, char *rules_filename, char *test_pcap_filename, char* log_filename) {
	int id;
	int err;
	bool write_header;
	struct pcap_context pcap_ctx;
	struct interface *interface;
	struct fw_cfg *config;

	pcap_ctx.log = NULL;
	pcap_ctx.runs = 1000; // How many times to run to collect runtimes stats.  May want to configure in the future.

	/*
	 * Open stats log
	 */
	if (log_filename) {
		write_header = (access(log_filename, F_OK) != 0);
		pcap_ctx.log = fopen(log_filename, "a");
		if (!pcap_ctx.log)
			errx(EX_SOFTWARE, "Failed to open stats log file %s: %s",
				log_filename,
				strerror(errno));
		if (write_header)
			fprintf(pcap_ctx.log, "rules,sha1,ret,min,average,max\n");
	}

	/*
	 * Open PCAP file
	 */
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_offline(test_pcap_filename, errbuf);
	if (handle == NULL)
		errx(EX_SOFTWARE, "Failed to open pcap file: %s", errbuf);

	/*
	 * Load subprogram
	 */
	ecbpf_mount_bpf_fs(); // Make sure bpffs is mounted (usually taken care of by root loader)
	interface = interface_new(NULL); // Null interface name creates a test interface
	ecbpf_ctx__set_subprogram_test(interface->ctx, true);

	err = ecbpf__subprogram_open(interface->ctx, program);
	if (err) {
		errx(EX_SOFTWARE, "Failed to load subprogram from %s", program);
	}

	err = ecbpf__subprogram_attach(interface->ctx, xstr(XDP_FW_PROG_NAME), XDP_PROG_ARRAY_IDX);
	if (err) {
		errx(EX_SOFTWARE, "Failed to attach subprogram");
	}

	config = cfg_new(rules_filename);
	rules_add(interface->ctx, config);
	pcap_ctx.config = config;

	pcap_ctx.prog_fd = ecbpf_ctx__get_subprogram_fd(interface->ctx);
	if (pcap_ctx.prog_fd < 0) {
		errx(EX_SOFTWARE, "Failed to get subprogram id");
	}

	/*
	 * Add in hasher
	 */
	pcap_ctx.hasher = hasher_new();
	if (pcap_ctx.hasher == NULL) {
		errx(EX_SOFTWARE, "Failed to create hasher");
	}

	/*
	 * Loop through pcap
	 */
	while(pcap_loop(handle, 0, &my_pcap_handler, (unsigned char *) &pcap_ctx));

	hasher_free(pcap_ctx.hasher);

	print_stats(interface);

	/*
	 * Detach
	 */
	err = ecbpf__subprogram_detach(interface->ctx, XDP_PROG_ARRAY_IDX);
	if (err) {
		errx(EX_SOFTWARE, "Failed to detach subprogram");
	}

	/*
	 * Cleanup
	 */
	cfg_free(config);

	if (pcap_ctx.log)
		fclose(pcap_ctx.log);
}
