#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <linux/limits.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <zmq.h>
#include "xdp_sampler_client.h"
#include "packet_sample.pb-c.h"

/* We should be using pcap/dlt.h for this, but
   xenial is crusty and these values are squirreled
   into pcap/bpf.h which we can't include since it
   conflicts with the system bpf.h */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */

pcap_t *handle;
pcap_dumper_t *dumper;
void *zmq_context;
void *zmq_sock;

bool debug;

void zmq_setup(char *port) {
	int err;
	char path[PATH_MAX];

    zmq_context = zmq_ctx_new();
    zmq_sock = zmq_socket(zmq_context, ZMQ_SUB);

	snprintf(path, PATH_MAX, "tcp://127.0.0.1:%s", port);
    err = zmq_connect(zmq_sock, path);
	zmq_setsockopt(zmq_sock, ZMQ_SUBSCRIBE, "", 0);


	if (err != 0) {
		errx(EX_SOFTWARE, "Failed to subscribe");
	}
}

int pcap_setup(char *output) {
	/* Open a dead handle for writing */
	handle = pcap_open_dead(DLT_EN10MB, XDP_SAMPLER_CAPLEN);
	if (handle == NULL) {
		fprintf(stderr, "Failed to create pcap handle.\n");
		return 1;
	}

	// The name "-" is a synonym for stdout.
	dumper = pcap_dump_open(handle, output);
	if (handle == NULL) {
		pcap_perror(handle, "Failed to create dumper");
		return 1;
	}
	return 0;
}

void teardown() {
	// pcap
	if (dumper)
		pcap_dump_close(dumper);
	if (handle)
		pcap_close(handle);

	// zmq
	if(zmq_sock)
		zmq_close(zmq_sock);
	if(zmq_context)
		zmq_ctx_destroy(zmq_context);
}

void sighandle() {
	teardown();
	exit(EX_OK);
}

void usage(int ret) {
	fprintf(stderr, "xdp_sampler_to_tcpdump:\n"
					"  --debug - Print debug messages\n"
					"  --count <n> - Quit after n packets\n"
					"  --port <port> - port xdp_sampler is listening on\n"
					"  --output <out> - Output to a file or - for stdout\n");

	exit(ret);
}

void recv_packet() {
	int size;
	uint8_t buf[4096];
	struct pcap_pkthdr hdr;

	PacketSample__PacketSample *sample;

	if (debug)
		fprintf(stderr, "Waiting to receive.  ");

	size = zmq_recv(zmq_sock, buf, sizeof(buf), 0);


	if (size < 0) {
		fprintf(stderr, "Error receiving message: %s\n", zmq_strerror(errno));
		return;
	}

	if (size > sizeof(buf)) {
		fprintf(stderr, "Error receiving message: Message too big\n");
		return;
	}

	sample = packet_sample__packet_sample__unpack(NULL, size, buf);
	if (!sample) {
		fprintf(stderr, "Failed to unpack message\n");
		return;
	}

	if (debug) {
		fprintf(stderr, "Got %i bytes from %s:%s with xdp_action_source: %i xdp_action: %i "
				"xdp_action_code: 0x%x xdp_action_meta: 0x%lx\n",
				size,
				sample->host_info->hostname,
				sample->packet_common->interface,
				sample->packet->xdp_action_source,
				sample->packet->xdp_action,
				sample->packet->xdp_action_code,
				sample->packet->xdp_action_meta);
	}

	hdr.ts.tv_sec = sample->packet->tv_sec;
	hdr.ts.tv_usec = sample->packet->tv_nsec / 1000;
	hdr.caplen = sample->packet->pkt.len;
	hdr.len = sample->packet->len;

	pcap_dump((u_char*) dumper, &hdr, sample->packet->pkt.data);

	packet_sample__packet_sample__free_unpacked(sample, NULL);

	/* Not sure we need to flush */
	if(pcap_dump_flush(dumper)) {
		pcap_perror(handle, "Failed to flush dumper");
		teardown();
	}
}

int main(int argc, char **argv) {
	char *output = NULL;
	char *port = NULL;
	char *endptr;
	int err = 0;
	int count = -1;
	int opt;
	int option_index = 0;

	struct option options[] = {
		{ "output", required_argument, 0, 'o' },
		{ "port", required_argument, 0, 'p' },
		{ "count", required_argument, 0, 'c' },
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt =
		getopt_long(argc, argv, "s:o:c:h", options,
			    &option_index)) != -1) {

		switch (opt) {
		case 0:
			// flag set
			break;
		case 'd':
			debug = true;
			break;
		case 'o':
			output = strdup(optarg);
			break;
		case 'p':
			port = strdup(optarg);
			break;
		case 'c':
			count = strtol(optarg, &endptr, 0);
			if (*endptr || endptr == optarg || count <= 0) {
				errx(EX_USAGE, "Invalid count: %s", optarg);
				err = 1;
				goto done;
			}
			break;
		default:
			usage(0);
			break;
		}
	}

	if (output == NULL) {
		err = 1;
		fprintf(stderr, "Missing required argument --output\n");
		goto done;
	}

	if (port == NULL) {
		err = 1;
		fprintf(stderr, "Missing required argument --port\n");
		goto done;
	}

	pcap_setup(output);
	free(output);
	zmq_setup(port);
	free(port);

	if (signal(SIGTERM, sighandle) || signal(SIGPIPE, sighandle) || signal(SIGINT, sighandle)) {
		err = 1;
		perror("Failed to setup signal handler");
		goto done;
	}

	// main loop...
	while (count != 0) {
		recv_packet();

		if (count < 0) // no count speciifed
			continue;
		count--;
	}

done:
	teardown();
	return err;
}
