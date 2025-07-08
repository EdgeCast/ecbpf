#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <linux/types.h>
typedef __u16 __sum16;
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>

#include "libecbpf_internal.h"
#include "libecbpf.h"
#include "rootmaps.h"

#define SAMPLES 10000000

struct ipv4_packet {
	struct ethhdr eth;
	struct iphdr iph;
	struct tcphdr tcp;
} __attribute__((packed));


int main(void)
{
    char *file = "../xdp_root/xdp_root_kern.o";
    struct bpf_object *obj;
    int err, prog_fd;
    char buf[128];
    int sum = 0, max = 0;
    struct ipv4_packet pkt_v4; 
    LIBBPF_OPTS(bpf_test_run_opts, opts,
	.data_in = &pkt_v4,
	.data_size_in = sizeof(pkt_v4),
	.data_out = buf,
	.data_size_out = sizeof(buf),
	.repeat = 1,
    );

    struct ecbpf_ctx *ctx;

    ctx = ecbpf_ctx__new();
    err = ecbpf__load_root_program(ctx, file, xstr(ROOT_PROG_SEC));
    
    if (err) {
        fprintf(stderr, "Failed to load root program\n");
        fprintf(stderr, "err %d errno %d \n", err, errno);
		return EXIT_FAILURE;
    }

    prog_fd = ecbpf_ctx__get_root_prog_fd(ctx);

    for(int i=0; i<SAMPLES; i++) {
        err = bpf_prog_test_run_opts(prog_fd, &opts);
        if(err || opts.retval != XDP_PASS) {
            fprintf(stderr, "Failure encountered running testing program\n");
            fprintf(stderr, "err %d errno %d retval %d size %d\n", err, errno, opts.retval, opts.data_size_out);
            return EXIT_FAILURE;
        }
        sum += opts.duration;
        if(max < opts.duration)
            max = opts.duration;
        printf("%d\n", opts.duration);
    }
    fprintf(stderr, "Avg runtime %d ns\n", sum/SAMPLES);
    fprintf(stderr, "Max runtime %d ns\n", max);

    return EXIT_SUCCESS;
}
