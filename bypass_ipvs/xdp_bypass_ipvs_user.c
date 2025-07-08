/*
 * Program to load an XDP and tc filter eBPF program for each input and
 * output NIC to detect ipvs sessions.   These sessions are recorded in a
 * map and fast-forwarded at the XDP input point directly to the outbound
 * interface selected by ipvs.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <ctype.h>
#include <limits.h>
#include <sys/resource.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <libbpf.h>
#include <rootmaps.h>
#include <bpf.h>
#include <libecbpf.h>
#include "xdp_bypass_ipvs_common.h"

// Track all specified interfaces, inbound/Internet or outbound/non-Internet,
// with their attributes and hardware addresses.  Configure a maximum number
// of link indicies, consistent with the kernel's map.
typedef struct	interface_info_s {
	char	* ifname;
	int	ifindex;
	tc_interface_info_t tc_info;	// Used in 'tc' kernel BPF map.
} interface_info_t;

static interface_info_t cinterface_info[TC_MAX_LINKS];  // cmdline interfaces.
static interface_info_t minterface_info[TC_MAX_LINKS];	// Map/merged version.
// Always reference the current set of interfaces being dealt with.
static interface_info_t * interface_info = cinterface_info;

// Max interfaces, keep the next 3 lines in sync so sscanf invocations parse
// properly!
#define	MAX_IN_OUT_INTERFACES	4	// Max interfaces, keep next 2 in sync!
#define	SSCANF_FORMAT "%ms %ms %ms %ms"  // spaces instead of commas.
#define	SSCANF_ARGS &ifname[0],&ifname[1],&ifname[2],&ifname[3]

static	int	ifaddrscnt = 0;
static	int	ifinputcnt = 0;
static	int	ifoutputcnt = 0;
static	char	* ifname[MAX_IN_OUT_INTERFACES];
static	char	* ifname_addrs[2];
static	int	ifx_addrs[2];
static	int	load_flag = 0;
static	int	unload_flag = 0;
static	unsigned int xdp_flags = XDP_FLAGS_DRV_MODE;

// Location of kernel .o files needed, either current working directory or
// default to installed package location.  This is needed since kernel objects
// no longer reside with this user space application.
static	char	kernel_objs_path_def[] = "/usr/share/ecbpf/programs";
static	char	* kernel_objs_path = NULL;

static struct sockaddr_ll output_sll = {
	.sll_family = AF_PACKET,
	.sll_protocol = __bswap_constant_16(ETH_P_ALL),
	.sll_halen = ETH_ALEN,
};

// Where 'tc' command pins maps when loaded
#define	TC_GLOBAL_MAPS_PATH	"/sys/fs/bpf/tc/globals"

// 'tc' egress parameters for a specific eBPF program, so can add/replace/delete
// that one without adding duplicates or deleting all egress eBPF.
//
// Note: Values are arbitrary but similar to ones 'tc' selects by default.
#define	XDP_BYPASS_IPVS_TC_PREF	49000
#define	XDP_BYPASS_IPVS_TC_HANDLE 5

/* Parameter defaults/limits */
#define	INACTIVE_SECS	60	/* Default idle flow for re-resolution */
#define	INACTIVE_SECS_MAX 900	/* Max value ever used in ipvsadm */

/* Default inter-packet time to ipvs sample */
#define	SAMPLE_SECS	1	// ipvs may change servers, so detect quickly.
#define	SAMPLE_SECS_MAX (INACTIVE_SECS_MAX - 1) /* Must be less than inactive */

// Various default rates/limits for inbound/Internet-facing rates.
#define	MAX_FLOW_RESETS_DEF	4000	// Total reset PPS to send to Internet.
#define	MAX_RESETS_EPOCH_DEF	8	// Epochs/second fraction for resets.
#define	RX_CPUS_DEF	8	// # of RX CPUs for inbound Internet packets.
#define	TARGET_PPS_DEF	8000000	// Entire system inbound @ 10G, G6.
#define	TARGET_PPS_SPIKE_DEF	5	// Spike percent over TARGET_PPS.
#define	TARGET_PPS_MAX_DEF	50	// Max percent over TARGET_PPS.
#define	WRAP_PACKETS_CNT_DEF	4096	// Default ring size to sample PPS at.

#define	NSECS_PER_SEC	(1000000000ull)

// Local configured interface addresses to exclude from fastpath processing.
static	__be32	v4_addrs[XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS];
static	struct in6_addr v6_addrs[XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS];

// Local addresses to exclude from fastpath which are not part of the
// configured interfaces, such as on "lo" for local-only VIPs.
typedef struct	af_inetaddr_s {
	int	ai_family;
	union	{
	__be32	ai_ip4;
	__be32	ai_ip6[4];
	struct in_addr ai_in4;
	struct in6_addr ai_in6;
	};
} af_inetaddr_t;

static af_inetaddr_t * ex_addrsp = NULL;
static unsigned int ex_addrscnt = 0;
static unsigned int ex_mode = 0;

// Command-line options may overwrite the defaults here.
// TODO: Make all items uniform, to provide lower-maintenance diffs/merge.
static	xdp_bypass_params_t xdp_bypass_params_default = {
        // Nanoseconds of inactivity to invoke flow re-resolution
        .inactive_nsecs = INACTIVE_SECS * NSECS_PER_SEC,
        // Nanoseconds between packet samples to keep alive ipvs state.
        .sample_nsecs = SAMPLE_SECS * NSECS_PER_SEC,
        .monitor_only = 0,	// Do processing/stats, but XDP_PASS if set.
        .use_xdp_tx = 1,	// XDP_TX on same NIC, otherwise bpf redirect.
        .vlan_hdr_tag = -1,	// VLAN id value to use, default -1 disables.
	.mode_progarray = 1,	// Use program array, else 0 for NIC or SKB.
	.limit_rates = 0,	// Do Inbound/outbound rate limits per settings.

	// These are typically recalculated for the running CPU but these
	// initializations provide an example of some default settings (G6).
	// Note the probability table initialized to zero (100% keep packets)
	// and divsor set to a high value to yield a low index assumes keeping
	// the packets.

	// Default per-CPU share of resets and further divide by the fraction
	// of a second that the "epoch" measurements are taken.
	.out_rsts = (MAX_FLOW_RESETS_DEF / (32 - RX_CPUS_DEF))
	/ MAX_RESETS_EPOCH_DEF,
	.out_rsts_epoch_ns = NSECS_PER_SEC / MAX_RESETS_EPOCH_DEF,

	// Defaults for sample/wrap count and associated target time.
	.in_wrap_cnt = WRAP_PACKETS_CNT_DEF, // Sample count, or ring size.

	.wrap_target_ns = (NSECS_PER_SEC * (__u64)WRAP_PACKETS_CNT_DEF)
	/ ((__u64)TARGET_PPS_DEF
	/ RX_CPUS_DEF), // Nano-seconds per default ring size.

	.wrap_min_ns = (NSECS_PER_SEC * (__u64)WRAP_PACKETS_CNT_DEF)
	/ (((TARGET_PPS_DEF * (100 + TARGET_PPS_SPIKE_DEF)) / 100)
	/ RX_CPUS_DEF),	// nsecs wrap per ring at spike rate.

	// Items for (re)calculating the above, saved for persistence in map.
	.rx_cpus = RX_CPUS_DEF,	// Default/reasonable value for RX IRQ CPUs.
	.inbound_pps = TARGET_PPS_DEF,	// Default inbound target pps.
	.inbound_spike = TARGET_PPS_SPIKE_DEF,	// Spike percent above pps.
	.inbound_max = TARGET_PPS_MAX_DEF,	// Max percent above pps.
	.max_reset_pps = MAX_FLOW_RESETS_DEF,	// System RST pps.
};

// Parameters that vary from above defaults, based on command line options
static	xdp_bypass_params_t xdp_bypass_params;

// Flags to individually track parameters to update
// TODO: Above uniformity comment would be helpful, track by array/indices
static	int	inactive_nsecs_flag = 0;
static	int	inbound_pps_flag = 0;
static	int	inbound_spike_flag = 0;
static	int	inbound_max_flag = 0;
static	int	in_wrap_cnt_flag = 0;
static	int	max_reset_pps_flag = 0;
static	int	mode_progarray_flag = 0;
static	int	monitor_only_flag = 0;
static	int	limit_rates_flag = 0;
static	int	rx_rps_cpus_flag = 0;
static	int	sample_nsecs_flag = 0;
static	int	use_xdp_tx_flag = 0;
static	int	vlan_hdr_tag_flag = 0;

// Latest copy of parameters from actual pinned map
static	xdp_bypass_params_t xdp_bypass_params_curr;
static	int	xdp_bypass_params_curr_pinned;

// Miscellaneous global/state variables
static	int	mapinfo_init;	// Maps have been opened
static	int	tc_loaded = 0;	// This program (re)loaded tc egress eBPF.
static	int	xdp_loaded = 0;	// This program (re)loaded XDP inbound eBPF.
static	enum prog_array_idxs xdp_prog_array_idx = XDP_IPVS_BYPASS_IDX;


/* Definitions and statics to track processing of the required data maps. */

/* Define indicies into Map Info array for each of our data maps. */
enum {
	MAP_IDX_PARAMS = 0,
	MAP_IDX_STATS,
	MAP_IDX_TUPLES,
	MAP_IDX_INTERFACES,
	MAP_IDX_FWM,
	MAP_IDX_V4LADDRS,
	MAP_IDX_V6LADDRS,
	MAP_IDX_IN_RATES,
	MAP_IDX_OUT_RATES
};

typedef struct {
	const char * mi_name; // Map's ELF symbol name, as a string
	int	mi_fd;	// File descriptor for user or kernel reference
	struct bpf_map * mi_obj; // Opaque map object pointer
} mapinfo_t ;

static	mapinfo_t mapinfo[] = {
	[MAP_IDX_PARAMS]	= {XBI_QUOTE_SYM(XBI_PARAMS_MAP_NAME)},
	[MAP_IDX_STATS]		= {XBI_QUOTE_SYM(XBI_STATS_MAP_NAME)},
	[MAP_IDX_TUPLES]	= {XBI_QUOTE_SYM(XBI_TUPLES_MAP_NAME)},
	[MAP_IDX_INTERFACES]	= {XBI_QUOTE_SYM(XBI_INTERFACES_MAP_NAME)},
	[MAP_IDX_FWM]		= {XBI_QUOTE_SYM(XBI_FWM_MAP_NAME)},
	[MAP_IDX_V4LADDRS]	= {XBI_QUOTE_SYM(XBI_V4LADDRS_MAP_NAME)},
	[MAP_IDX_V6LADDRS]	= {XBI_QUOTE_SYM(XBI_V6LADDRS_MAP_NAME)},
	[MAP_IDX_IN_RATES]	= {XBI_QUOTE_SYM(XBI_INBOUND_RATES_MAP_NAME)},
	[MAP_IDX_OUT_RATES]	= {XBI_QUOTE_SYM(XBI_OUTBOUND_RATES_MAP_NAME)}
};

static	int	check_if_slave_all(void);
static	int	check_tc_running(char * bpf_filename, char * if_name);
static	int	check_tc_running_all(char * bpf_filename);
static	int	check_xdp_running(int ifindex, char * if_name);
static	int	check_xdp_running_all(void);
static	void	detach_xdp_prog_all(void);
static	void	display_nobypass_addrs(char ** argv);
static	void	display_params_map(char ** argv);
static	void	display_stats_maps(char ** argv, int secs, int cnt, int flows);
static  void    statsd_stats_maps (char ** argv);
static  void    statsd_send_gauge (char * metric_name, __u64 value);
static	int	get_bpf_info(int prog_id, struct bpf_prog_info * infop
		, char ** timestrp);
static	int	get_hw_ifaddr(char * ifname, int ifindex, unsigned char * hwaddr
		, int hwlen);
static	void	init_from_intf_map(void);
static	void	load_current_nop_xdp(int if_index);
static	void	load_current_nop_xdp_all(void);
static	void	load_current_tc_xdp(char ** argv, int force_flag);
static	int	open_pinned_maps(char ** argv, int exit_on_error);
static	int	read_current_params_map();
static	void	replace_tc_bpf(char * bpf_filename, char * ifname);
static	void	replace_tc_bpf_all(char * bpf_filename);
static	void	replace_xdp_bpf(char * bpf_filename
		, struct bpf_object * kern_objs
		, struct bpf_program * inbound_prog_obj
		, struct bpf_program * dummy_prog_obj
		, interface_info_t * intfp);
static	void	replace_xdp_bpf_all(char * bpf_filename);
static	void	unload_tc_xdp_unpin(char ** argv, int force_flag);
static	void	update_params_addrs_maps(void);
static	void	update_params_in_pps(void);
static	void	update_params_out_pps(void);
static	void	usage_and_exit(char * arg0, char * lasterror);
static	int	v4_get_ifaddrs(int ifx, __be32 * v4_addrs, int numaddrs);
static	int	v6_get_ifaddrs(int ifx, struct in6_addr * v6_addrs
		, int numaddrs);

static struct rlimit rlimit_unlimited = {RLIM_INFINITY, RLIM_INFINITY};

#define	MAX_FILENAME	256	// 255 characters + null

static struct option long_options[] = {
	{"display-excluded-addrs", no_argument, 0, 'B'},
	{"excluded-addrs", required_argument, 0, 'e'},
	{"flows-display-tcp", no_argument, 0, 'f'},
	{"force", no_argument, 0, 'F'},
	{"load", no_argument, 0, 'L'},
	{"parameters-display", no_argument, 0, 'P'},
	{"statistics", no_argument, 0, 'S'},
	{"skb-mode", no_argument, 0, 'T'},
	{"unload", no_argument, 0, 'U'},
	{"addrs-ifs", required_argument, 0, 'a'},
	{"cpus-rx-rps", required_argument, 0, 'c'},
	{"inbound-ifs", required_argument, 0, 'i'},
	{"limit-rates", required_argument, 0, 'l'},
	{"max-resets-pps", required_argument, 0, 'm'},
	{"monitor-mode", required_argument, 0, 'M'},
	{"outbound-ifs", required_argument, 0, 'o'},
	{"program-array-mode", required_argument, 0, 'p'},
	{"redirect-mode", required_argument, 0, 'R'},
	{"inactive-seconds-xdp", required_argument, 0, 'r'},
	{"sample-seconds-ipvs", required_argument, 0, 's'},
	{"inbound-pps", required_argument, 0, 't'},
	{"vlan", required_argument, 0, 'v'},
	{"wrap-packets-count", required_argument, 0, 'w'},
	{"statsd-enable", no_argument, 0, 'z'},
	{0, 0, 0, 0}
};

int
main (int argc, char **argv)
{
	int	bypass_flag = 0;
	char	* cmdnamep;
	char	* cmdpathp;
	int	cnt;
	int	elf_fd;
	Elf_Data * elf_datap;
	Elf_Scn	* elf_scnp;
	char	* endptr;
	Elf	* ep;
	int	err;
	char	* extra_intfs;
	int	flow_samples = 0;
	int	force_flag = 0;
	int	idx;
	int	ifx;
	__u32	inactive_secs = INACTIVE_SECS;
	interface_info_t * intfp;
	ulong	in_wrap_cnt;
	char	kobjs_path[MAX_FILENAME];
	char	map_path[PATH_MAX];
	ulong	max_reset_pps;
	int	opt;
	int	parameters_flag = 0;
	uint	percent;
	uint	sample_secs = SAMPLE_SECS;
	int	stats_flag = 0;
	int	stats_secs;
	int	stats_cnt;
	uint	total_cpus;
	char	* valp;
	ulong	wrap_packets_cnt = WRAP_PACKETS_CNT_DEF;
	int statsd_flag = 0;

	// Interfaces and at least one other option is needed.
	if (argc == 1)
		usage_and_exit(*argv, NULL);

	// Init working params structure with defaults that can be overridden
	memcpy((void *)&xdp_bypass_params, (void *)&xdp_bypass_params_default
	, sizeof(xdp_bypass_params));

	// Required runtime initialization of parameters.
	total_cpus = get_nprocs();
	xdp_bypass_params.rps_cpus = total_cpus - xdp_bypass_params.rx_cpus;

	// Parse command line and set up all map parameters and run options.
	while ((opt = getopt_long(argc, argv
	, "BfFLPSTUa:c:e:i:l:o:m:M:p:R:r:s:t:v:w:z", long_options, NULL))
	!= -1) {
		if (opt == -1)
		    break;

		switch (opt) {
		case 'a':
			// Up to 2 interfaces to gather IP[v6] addresses from
			// may be specified on the bypass addresses option to
			// not be subjected to fastpath processing:
			//
			// -a <cddrs-ifname>[,addrs-ifname>]

			// Translate commas into white-space for each
			// interface string then parse them out.
			while ((valp = strchr(optarg, ','))) {
				*valp = ' ';
				if (valp[1] == ',') {
					usage_and_exit(*argv, "Address interfa"
					"ces, consecutive commas");
				}
			}
			ifname_addrs[0] = ifname_addrs[1] = NULL;
			// Don't worry about interface length here.  if_nametoindex will
			// validate the strings.  The length trips up the clang 15
			// verifier.
			cnt = sscanf(optarg, "%ms %ms %ms"
			, &ifname_addrs[0], &ifname_addrs[1], &extra_intfs);

			switch (cnt) {
			default:
				if (cnt < 1) {
					usage_and_exit(*argv
					, "No -a interfaces specified");
				}
				if (cnt > 2) {
					printf("\n*** Extra address(es) "
					"interface(s) '%s' ignored ***\n\n"
					, extra_intfs);
					cnt = 2;
				}
				__attribute__((fallthrough));
			case 1:
			case 2:
				ifx_addrs[0] = if_nametoindex(ifname_addrs[0]);
				if (!ifx_addrs[0]) {
					usage_and_exit(*argv
					, "Invalid -a interface specified");
				}
				if (ifname_addrs[1]) {
					ifx_addrs[1]
					= if_nametoindex(ifname_addrs[1]);
					if (!ifx_addrs[1]) {
						usage_and_exit(*argv
						, "Invalid -a interface "
						"specified");
					}
				}
				ifaddrscnt = cnt;
				for (idx = 0; idx < ifaddrscnt; idx++) {
					intfp = &interface_info[ifx_addrs[idx]];
					intfp->tc_info.if_flags
					|= TC_INTF_F_BYPASS;
					intfp->ifindex = ifx_addrs[idx];
					intfp->ifname = ifname_addrs[idx];
				}

				break;
			}
			break;
		case 'B':
			bypass_flag = 1;
			break;
		case 'c':
			// RX and RPS CPUs may be specified on the -c option:
			//
			// -c|--cpus-rx-rps <rx-cpus>[, rps-cpus]
			total_cpus = get_nprocs();
			cnt = sscanf(optarg, "%hu,%hu"
			, &xdp_bypass_params.rx_cpus
			, &xdp_bypass_params.rps_cpus);
			switch (cnt) {
			case 1:
				if (xdp_bypass_params.rx_cpus < 1
				|| xdp_bypass_params.rx_cpus >= total_cpus) {
					usage_and_exit(*argv
					, "Out of range -c/--rx_rps_cpus "
					"specified - RX CPUs");
				}

				// Assumes RPS CPU for everything not RX.
				xdp_bypass_params.rps_cpus = total_cpus
				- xdp_bypass_params.rx_cpus;
				rx_rps_cpus_flag = 1;
				break;
			case 2:
				if (xdp_bypass_params.rx_cpus < 1
				|| xdp_bypass_params.rx_cpus >= total_cpus
				|| xdp_bypass_params.rps_cpus < 1
				|| xdp_bypass_params.rps_cpus >= total_cpus) {
					usage_and_exit(*argv
					, "Out of range -c/--rx_rps_cpus "
					"specified");
				}
				rx_rps_cpus_flag = 1;
				break;
			default:
				usage_and_exit(*argv
				, "Invalid -c/--rx_rps_cpus specified");
			}
			break;

		case 'e': {
			char	* addrlistp;

			if (ex_mode) {
				usage_and_exit(*argv, "Invalid to specify "
				"multiple -e|--excluded-addrs options");
			}

			// Excluded address(es) processing, currently an
			// "add" or "de[ete]" of the specified addresses is
			// supported.
			if (!strncasecmp(optarg, "add", 3))
				ex_mode = 1;
			else if (!strncasecmp(optarg, "del", 3)
			|| !strncasecmp(optarg, "delete", 6))
				ex_mode = 2;
			else {
				usage_and_exit(*argv
				, "Invalid command to -e|--excluded-addrs");
			}

			// Determine how many IPv4/IPv6 addresses exist in the
			// following argument and separate each one with a NULL
			// character.
			if (optind >= argc
			|| (addrlistp = argv[optind]), !addrlistp
			|| *addrlistp == '\0') {
				usage_and_exit(*argv, "Missing address[es] list"
				" for -e|--excluded-addrs option");
			}

			valp = addrlistp;
			while ((valp = strchr(valp, ','))) {
				*valp = '\0';
				if (valp[1] == ',') {
					usage_and_exit(*argv, "Consecutive "
					"commas on excluded addresses arg");
				}
				valp++;
				ex_addrscnt++;
			}
			if (!ex_addrscnt++) {
				if (strlen(addrlistp) < 3) {
					usage_and_exit(*argv, "Invalid address"
					" for exclude list");
				}
			}

			// Allocate memory for all addresses found.
			ex_addrsp = (af_inetaddr_t *)malloc(ex_addrscnt
			* sizeof(af_inetaddr_t));
			if (!ex_addrsp) {
				usage_and_exit(*argv, "Unable to allocate "
				"memory for addresses to be excluded");
			}

			// Convert each address string segment created above
			// into the binary in[6] form appropriate for the
			// address-separation character found (dots or colons).
			valp = addrlistp;
			for (idx = 0 ; idx < ex_addrscnt ; idx++) {
				if ((strchr(valp, '.') && strchr(valp, ':'))
				|| (!strchr(valp, '.') && !strchr(valp, ':'))
				|| strchr(valp, '/')) {
					usage_and_exit(*argv, "Invalid excluded"
					" address format/prefix or v4-mapped");
				} else if (strchr(valp, '.')) {
					ex_addrsp[idx].ai_family = AF_INET;
					if (!inet_pton(AF_INET, valp
					, (void *)&ex_addrsp[idx].ai_in4)) {
						usage_and_exit(*argv, "Invalid "
						"IPv4 excluded address.");
					}
				} else {
					ex_addrsp[idx].ai_family = AF_INET6;
					if (!inet_pton(AF_INET6, valp
					, (void *)&ex_addrsp[idx].ai_in6)) {
						usage_and_exit(*argv, "Invalid "
						"IPv6 excluded address.");
					}
				}

				// Step past null-terminated address string.
				valp += strlen(valp) + 1;
			}
			}
			// "ate" address/extra argument, skip to next option.
			optind++;
			break;
		case 'f':
			flow_samples = 1;
			break;
		case 'F':
			force_flag++;
			break;
		case 'i':
			// Several interfaces may be specified on the -i:
			//
			// -i|--inbound-ifs <ifname>[,<ifname>...]

			// Parse up through MAX_IN_OUT_INTERFACES names.
			// Do compile-time check that properly configured.
			if (sizeof(ifname) / sizeof(ifname[0])
			!= MAX_IN_OUT_INTERFACES) {
				printf("\n*** Invalid build of %s ***\n\n"
				, *argv);
				exit(EXIT_FAILURE);
			}

			// Translate commas into white-space for each
			// interface string then parse them out.
			while ((valp = strchr(optarg, ','))) {
				*valp = ' ';
				if (valp[1] == ',') {
					usage_and_exit(*argv, "Inbound interfa"
					"ces, consecutive commas");
				}
			}
			ifinputcnt = sscanf(optarg
			, SSCANF_FORMAT " %ms", SSCANF_ARGS, &extra_intfs);

			if (ifinputcnt < 1)
				usage_and_exit(*argv, "No -i interfaces");
			if (ifinputcnt > MAX_IN_OUT_INTERFACES) {
				printf("Extra input interface(s) '%s' ignored\n"
				, extra_intfs);
				ifinputcnt = MAX_IN_OUT_INTERFACES;
			}

			for (idx = 0 ; idx < ifinputcnt; idx++) {
				ifx = if_nametoindex(ifname[idx]);
				if (!ifx) {
					usage_and_exit(*argv
					, "Invalid XDP inbound interface");
				}
				if (ifx > TC_MAX_LINKS) {
					printf("Interface %s link index exceeds"
					" map size index\n", ifname[idx]);
					usage_and_exit(*argv
					, "Invalid XDP inbound interface");
				}

				intfp = &interface_info[ifx];
				if (intfp->ifindex
				&& (intfp->tc_info.if_flags & TC_INTF_F_INTERNET
				)) {
					usage_and_exit(*argv
					, "Interface repeated on -i");
				}

				intfp->ifindex = ifx;
				intfp->ifname = ifname[idx];
				intfp->tc_info.if_flags |= TC_INTF_F_INTERNET;
				if (get_hw_ifaddr(ifname[idx], ifx
				, intfp->tc_info.hwaddr, ETH_ALEN)) {
					usage_and_exit(*argv
					, "Error on hw address of inbound "
					"interface");
				}
			}
			break;
		case 'l':
			if (!strncasecmp(optarg, "off", 3))
				xdp_bypass_params.limit_rates = 0;
			else if (!strncasecmp(optarg, "on", 2))
				xdp_bypass_params.limit_rates = 1;
			else {
				usage_and_exit(*argv
				, "Invalid option for -l (limit rates) flag");
			}
			limit_rates_flag = 1;
			break;
		case 'L':
			load_flag = 1;
			break;
		case 'm':
			// Max RSTs/rejects to allow per-second:
			//
			// -m|--max-resets-pps <packets-per-second>
			max_reset_pps = strtoul(optarg, NULL, 0);
			if (!max_reset_pps || max_reset_pps >= UINT_MAX) {
				usage_and_exit(*argv
				, "Invalid max_reset_pps value");
			}
			xdp_bypass_params.max_reset_pps = (__u32)max_reset_pps;
			max_reset_pps_flag = 1;
			break;
		case 'M':
			if (!strncasecmp(optarg, "off", 3))
				xdp_bypass_params.monitor_only = 0;
			else if (!strncasecmp(optarg, "on", 2))
				xdp_bypass_params.monitor_only = 1;
			else {
				usage_and_exit(*argv
				, "Invalid option for -M (monitor-only) flag");
			}
			monitor_only_flag = 1;
			break;
		case 'o':
			// Several interfaces may be specified on the -o:
			//
			// -o|--outbound-ifs <ifname>[,<ifname>...]

			// Parse up through MAX_IN_OUT_INTERFACES names.

			// Translate commas into white-space for each
			// interface string then parse them out.
			while ((valp = strchr(optarg, ','))) {
				*valp = ' ';
				if (valp[1] == ',') {
					usage_and_exit(*argv, "Outbound interfa"
					"ces, consecutive commas");
				}
			}
			ifoutputcnt = sscanf(optarg
			, SSCANF_FORMAT " %ms", SSCANF_ARGS, &extra_intfs);

			if (ifoutputcnt < 1)
				usage_and_exit(*argv, "No -o interfaces");
			if (ifoutputcnt > MAX_IN_OUT_INTERFACES) {
				printf("\n*** Extra output interface(s) '%s' "
				"ignored ***\n\n"
				, extra_intfs);
				ifoutputcnt = MAX_IN_OUT_INTERFACES;
			}

			for (idx = 0 ; idx < ifoutputcnt; idx++) {
				ifx = if_nametoindex(ifname[idx]);
				if (!ifx) {
					usage_and_exit(*argv
					, "Invalid tc outbound interface");
				}
				if (ifx > TC_MAX_LINKS) {
					printf("Interface %s link index exceeds"
					" map size index\n", ifname[idx]);
					usage_and_exit(*argv
					, "Invalid tc outbound interface");
				}

				intfp = &interface_info[ifx];
				if (intfp->ifindex
				&& (intfp->tc_info.if_flags & TC_INTF_F_INSIDE
				)) {
					usage_and_exit(*argv
					, "Interface repeated on -o");
				}

				intfp->ifindex = ifx;
				intfp->ifname = ifname[idx];
				intfp->tc_info.if_flags |= TC_INTF_F_INSIDE;
				if (get_hw_ifaddr(intfp->ifname, ifx
				, intfp->tc_info.hwaddr, ETH_ALEN)) {
					usage_and_exit(*argv
					, "Error on hw address of outbound "
					"interface");
				}
			}
			break;
		case 'P':
			parameters_flag = 1;
			break;
		case 'p':
			if (!strncasecmp(optarg, "off", 3))
				xdp_bypass_params.mode_progarray = 0;
			else if (!strncasecmp(optarg, "on", 2))
				xdp_bypass_params.mode_progarray = 1;
			else {
				usage_and_exit(*argv
				, "Invalid option for -p (program array) flag");
			}
			mode_progarray_flag = 1;
			break;
		case 'R':
			if (!strncasecmp(optarg, "off", 3))
				xdp_bypass_params.use_xdp_tx = 1;
			else if (!strncasecmp(optarg, "on", 2))
				xdp_bypass_params.use_xdp_tx = 0;
			else {
				usage_and_exit(*argv
				, "Invalid option for -R (BPF redirect) flag");
			}
			use_xdp_tx_flag = 1;
			break;
		case 'r':
			inactive_secs = (__u32)strtol(optarg, &endptr, 0);
			if (*endptr != '\0' || *optarg == '\0'
			|| inactive_secs > INACTIVE_SECS_MAX) {
				usage_and_exit(*argv, "Invalid inactivity "
				"seconds value specified via -r");
			}
			xdp_bypass_params.inactive_nsecs = (__u64)inactive_secs
			* NSECS_PER_SEC;
			inactive_nsecs_flag = 1;
			break;
		case 's':
			sample_secs = (uint)strtol(optarg, &endptr, 0);
			if (*endptr != '\0' || *optarg == '\0'
			|| sample_secs < 1 || sample_secs > SAMPLE_SECS_MAX
			|| sample_secs > inactive_secs) {
				usage_and_exit(*argv, "Invalid sampling time "
				"specified via -s");
			}
			xdp_bypass_params.sample_nsecs = (__u64)sample_secs
			* NSECS_PER_SEC;
			sample_nsecs_flag = 1;
			break;
		case 'S':
			// [seconds [count]] are optional, check argv[s] in-line
			// but will at least do a stats set, default to one with
			// no interval seconds.
			stats_flag = 1;
			stats_cnt = 1;
			stats_secs = 0;
			if (optind >= argc)
				break;
			valp = argv[optind];
			if (*valp == '-' || !isdigit(*valp))
				break;
			stats_secs = (__u32)strtol(valp, &endptr, 0);
			if (*endptr != '\0') {
				usage_and_exit(*argv, "Invalid time specified "
				"by -S");
			}
			optind++;

			// Seconds specified, default to near-infinite count
			stats_cnt = INT_MAX;
			if (optind >= argc)
				break;
			valp = argv[optind];
			if (*valp == '-' || !isdigit(*valp))
				break;
			stats_cnt = (__u32)strtol(valp, &endptr, 0);
			if (*endptr != '\0') {
				usage_and_exit(*argv, "Invalid count specified "
				"by -S");
			}
			optind++;
			break;
		case 't':
			// Total inbound packet rates, including spikes, and
			// maximum before rate-limiting is applied to unknown
			// (new) flows:
			//
			// -t|--inbound_pps <inbound-pps>[+<spike>[+max]]
			cnt = sscanf(optarg, "%u+%u+%u"
			, &xdp_bypass_params.inbound_pps
			, &xdp_bypass_params.inbound_spike
			, &xdp_bypass_params.inbound_max);
			switch (cnt) {
			case 3:
				inbound_max_flag = 1;
				__attribute__((fallthrough));
			case 2:
				inbound_spike_flag = 1;
				__attribute__((fallthrough));
			case 1:
				// TOCONSIDER: Check rates with actual NICs'
				// speeds and/or bondings?
				// For now, bound rates between 3-90Mpps.
				if (xdp_bypass_params.inbound_spike > 100
				|| xdp_bypass_params.inbound_max > 100
				|| !xdp_bypass_params.inbound_pps
				|| xdp_bypass_params.inbound_pps < 3*1024*1024
				|| xdp_bypass_params.inbound_pps > 90*1024*1024)
				{
					usage_and_exit(*argv
					, "Invalid target_pps value");
				}
				inbound_pps_flag = 1;
				break;
			default:
				usage_and_exit(*argv
				, "Invalid target_pps or percentage value(s)");
			}
			break;
		case 'T':
			xdp_flags = XDP_FLAGS_SKB_MODE;
			break;
		case 'U':
			unload_flag = 1;
			break;
		case 'v':
			xdp_bypass_params.vlan_hdr_tag
			= (int)strtol(optarg, &endptr, 0);
			if (*endptr != '\0' || *optarg == '\0'
			|| xdp_bypass_params.vlan_hdr_tag < -1
			|| xdp_bypass_params.vlan_hdr_tag > 4095 )
				usage_and_exit(*argv, "Invalid VLAN id value");
			vlan_hdr_tag_flag = 1;
			break;
		case 'w':
			in_wrap_cnt = strtoul(optarg, NULL, 0);
			if (in_wrap_cnt < 128 || in_wrap_cnt >= UINT_MAX) {
				usage_and_exit(*argv
				, "Invalid -w/--wrap-packets-count "
				"sample/wrap packets");
			}
			xdp_bypass_params.in_wrap_cnt = (__u32)in_wrap_cnt;
			in_wrap_cnt_flag = 1;
			break;
		case 'z':
			statsd_flag = 1;
			break;
		default:
			usage_and_exit(*argv, "Invalid option");
		}
	}

	// Some sanity checks of argument combinations before proceeding.
	// Don't need interfaces (yet?) for stats and other maps operations.
	if (argc > optind) {
		usage_and_exit(*argv
		, "Non-flag arguments/options are present, check command.");
	}

	// Discover location/version of kernel objects, which may require
	// override via "force_flag" setting before the load/unload usages.
	cmdpathp = strdup(argv[0]);
	if (!cmdpathp || !(cmdnamep = basename(cmdpathp))) {
		printf("\n*** Allocation failed on command parsing, change "
		"directory? ***\n\n");
		exit(EXIT_FAILURE);
	}
	err = snprintf(kobjs_path, sizeof(kobjs_path), "%s_xdp_kern.o"
	, cmdnamep);
	if (err <= 0 || err > sizeof(kobjs_path)) {
		printf("\n*** Unable to format string for looking up kernel "
		"objects. ***\n\n");
		exit(EXIT_FAILURE);
	}

	if (access(kobjs_path, R_OK)) {
		// Not in current working directory, try default location.
		kernel_objs_path = kernel_objs_path_def;
		err = snprintf(kobjs_path, sizeof(kobjs_path)
		, "%s/%s_xdp_kern.o", kernel_objs_path, cmdnamep);
		if (err <= 0 || err > sizeof(kobjs_path)) {
			printf("\n*** Unable to format string for looking up "
			"kernel objects in default location. ***\n\n");
			exit(EXIT_FAILURE);
		}

		if (access(kobjs_path, R_OK)) {
			printf("\n*** Can not find kernel objects in current "
			"or default locations. ***\n\n");
			exit(EXIT_FAILURE);
		}
	}

	// Have location, check out maps version match.
	ep = ecbpf_elf_open_filename(kobjs_path, &elf_fd);
	if (!ep) {
		printf("\n*** Unable to open ELF successfully. ***\n\n");
		exit(EXIT_FAILURE);
	}

	elf_scnp = ecbpf_elf_find_section(ep, SHT_PROGBITS
	, "XDP_BYPASS_IPVS_COMMON_H_SHA256");
	if (!elf_scnp) {
		printf("\n*** Unable to find maps version ELF section. "
		"***\n\n");
		exit(EXIT_FAILURE);
	}

	// Dedicated section for one data element to retrieve.
	elf_datap = elf_getdata(elf_scnp, NULL);
	if (!elf_datap
	|| elf_datap->d_size != sizeof(XDP_BYPASS_IPVS_COMMON_H_SHA256)
	|| !elf_datap->d_buf) {
		printf("\n*** Invalid maps version string in ELF section. "
		"***\n\n");
		exit(EXIT_FAILURE);
	}

	// Finally, check if kernel code matches loader's maps build version.
	// Only the XDP object is checked, it is assumed the TC and NOP
	// objects are also present and from the same build.
	if (strcmp(elf_datap->d_buf, XDP_BYPASS_IPVS_COMMON_H_SHA256)) {
		if (force_flag >=2)
			force_flag--;
		else {
			printf("\nMaps version mismatch loader/admin vs "
			"%s_xdp_kern.o, versions:\n\n"
		        "  Running: %s\n  Kobject: %s\n\n", cmdnamep
			, XDP_BYPASS_IPVS_COMMON_H_SHA256, (char *)elf_datap->d_buf);
			if (force_flag == 1) {
				printf("... continuing but last -F 'absorbed', "
				"additional -F required for ops like -L\n\n");
				force_flag--;
			} else {
				usage_and_exit(*argv
				, "One or more -F needed to continue.");
			}
		}
	}

	// Free up stuff from above.
	free(cmdpathp);
	elf_end(ep);
	close(elf_fd);

	// Additional sanity checks.
	if ((load_flag && unload_flag)
	|| (force_flag && !load_flag && !unload_flag)) {
		usage_and_exit(*argv
		, "Invalid -L|-U|-F usage.");
	}

	if (load_flag && (!ifinputcnt || !ifoutputcnt)) {
		usage_and_exit(*argv
		, "Missing needed interface(s) with -L usage.");
	}

	if (unload_flag
	&& ((!ifinputcnt && ifoutputcnt) || (ifinputcnt && !ifoutputcnt))) {
		usage_and_exit(*argv
		, "Both Internet/Inside interfaces OR neither for -U usage.");
	}

	if (!load_flag && !unload_flag
	&& (ifinputcnt || ifoutputcnt)) {
		usage_and_exit(*argv
		, "Interface options are invalid except with -L|-U usage.");
	}

	if (load_flag && !force_flag
	&& !ifx_addrs[0] && check_if_slave_all()) {
		usage_and_exit(*argv
		, "All interfaces are slaves and no -a address "
		"interface(s) (such as bond*) specified.  Use -F to force.");
	}

	if (flow_samples && !stats_flag) {
		usage_and_exit(*argv
		, "-f flow sampling requires -S statistics to be set.");
	}

	if (mode_progarray_flag && !load_flag) {
		usage_and_exit(*argv
		, "-p program array mode can only be used with -L (load).");
	}

	if (xdp_flags == XDP_FLAGS_SKB_MODE && !load_flag) {
		usage_and_exit(*argv
		, "-T SKB mode can only be used with -L (load).");
	}

	/*
	 * Validate stats structure is exact 64-bit multiple of counters to
	 * be collected/summed later, since that method depends on 64-bit
	 * array elements overlay.  Catch this here rather than wait until
	 * someone uses the stats option(s).
	 */
	if (sizeof(xdp_global_stats_t) & 7) {
		printf("xdp_global_stats_t not a multiple of 64-bit counters, "
		"unable to sum PER_CPU stats without code changes.\n");
		exit(EXIT_FAILURE);
	}

	/* Set associated memory limits unlimited, for large map sizes. */
	if (setrlimit(RLIMIT_MEMLOCK, &rlimit_unlimited)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		exit(EXIT_FAILURE);
	}

	// Perform requested operation(s).
	//
	// -L is performed first, updating any parameters as specified.
	// Then any requested parameters or stats displays are done.
	//
	// -U is performed last, preceded by any parameter updates.
	// Any parameter or stats displays also precede unloading.
	//
	// Non-load/unload operations modify parameters map and/or do the
	// requested displays.
	if (load_flag) {
		load_current_tc_xdp(argv, force_flag);
	} else if (unload_flag && force_flag) {
		// Force a full unload but if the maps are still accessible
		// continue on to allow the various displays to take place.
		// But if an error occurs here, skip displays and just force
		// the unload.
		if (open_pinned_maps(argv, 0) || read_current_params_map()) {
			printf("*** Map access errors, proceeding with full "
			"unload only.  ***\n"
			"*** Full interfaces must be specified. ***\n");
			unload_tc_xdp_unpin(argv, force_flag);
			exit(EXIT_SUCCESS);
		}
		init_from_intf_map();
	} else {
		(void)open_pinned_maps(argv, 1);
		err = read_current_params_map();
		if (err) {
			printf("Unexpected failure (%d)' %s' reading "
			"parameters  map: %s\n", err, strerror(err)
			, mapinfo[MAP_IDX_PARAMS].mi_name);
			exit(EXIT_FAILURE);
		}
		init_from_intf_map();
		update_params_addrs_maps();
	}

	if (parameters_flag)
		display_params_map(argv);

	if (bypass_flag)
		display_nobypass_addrs(argv);

	if (stats_flag)
		display_stats_maps(argv, stats_secs, stats_cnt, flow_samples);

	if (statsd_flag && !unload_flag)
		statsd_stats_maps(argv);

	if (unload_flag)
		unload_tc_xdp_unpin(argv, force_flag);

	exit(EXIT_SUCCESS);
}

//
// check_if_slave_all
//
// check all interfaces and see if there are any that aren't bonded slaves.
//
// 0 - At least one interface is not a slave.
// 1 - All slave interfaces.
static int
check_if_slave_all ()
{
	int	fd;
	int	idx;
	struct	ifreq	ifreq;

	fd = socket(AF_PACKET, SOCK_RAW, ETH_P_LOOPBACK);
	if (fd == -1) {
		perror("socket(AF_PACKET, SOCK_RAW, ETH_P_LOOPBACK) "
		"for SIOCGIFFLAGS");
		exit(EXIT_FAILURE);
		return 0;
	}

	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++) {
		if (!interface_info[idx].ifindex)
			continue;

		memset(ifreq.ifr_name, 0, sizeof(ifreq.ifr_name));
		strncpy(ifreq.ifr_name, interface_info[idx].ifname
		, sizeof(ifreq.ifr_name));

		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
			perror("ioctl(SIOCGIFFLAGS)");
			exit(EXIT_FAILURE);
		}

		if (!(ifreq.ifr_flags & IFF_SLAVE))
			return 0;
	}

	close(fd);
	return 1;
}

// Use "tc" command to determine if our eBPF program hooked on egress
//
// Either exits with error or returns:
//    0 - eBPF tc program is not running
//    1 - eBPF tc program at interface egress point
static int
check_tc_running (char * bpf_filename, char * ifname)
{
	int	cnt;
	char	bpf_basename[MAX_FILENAME];
	int	err;
	int	err_status;
	char	tc_cmdbuf[MAX_FILENAME + 100];

	/*
	 * Check that the kernel BPF object has been associated with the output
	 * interface egress point.  An error from either a tc failure or that
	 * the grep'ed BPF object is missing will look the same, a return of 1
	 * instead of the 0 for success (reverse of what function returns).
	 */
	strncpy(bpf_basename, bpf_filename, sizeof(bpf_basename));
	bpf_basename[sizeof(bpf_basename) - 1] = '\0';
	cnt = snprintf(tc_cmdbuf, sizeof(tc_cmdbuf)
	, "tc filter show dev %s egress | grep -q %s"
	, ifname, basename(bpf_basename));
	if (cnt < 0 || cnt >= sizeof(tc_cmdbuf)) {
		printf("Unable to set up 'tc' command to confirm egress hook "
		"is installed, command length overrun or output error: %d\n"
		, cnt);
		exit(EXIT_FAILURE);
	}

	err = system(tc_cmdbuf);
	err_status = WEXITSTATUS(err);
	if (!WIFEXITED(err) || err_status < 0 || err_status > 1) {
		// Error forking/exec'ing or something unexpected.  Give up.
		printf("Error launching tc command: %s\n"
		"    err: %d err_status: %d\n"
		, tc_cmdbuf, err, err_status);
		exit(EXIT_FAILURE);
	}

	if (err_status)
		return 0;
	return 1;
}

// check_tc_running_all
//
// Invoke check_tc_running() for all interfaces, inbound (Interface) or outbound
// (Server), for insertion of the "tc" eBPF program to either snoop on
// server-bound packets directed by ipvs or Internet-bound packets to detect
// reset flows.
//
// Returns:
//     0 - At least one interface does not have "tc" running.
//     1 - All interfaces have "tc" running.
static int
check_tc_running_all (char * bpf_filename)
{
	int	idx;
	interface_info_t * intfp;
	int	ret_status = 0;

	for (idx = 1 ; idx < TC_MAX_LINKS; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex || !(intfp->tc_info.if_flags
		& (TC_INTF_F_INTERNET | TC_INTF_F_INSIDE)))
			continue;
		ret_status = check_tc_running(bpf_filename, intfp->ifname);
		if (ret_status == 0)
			return 0;
	}

	return ret_status;
}

// Use "get link" function or program array to check if XDP hooked on interface
//
// Returns:
//    0 - eBPF XDP program is not running on interface
//    1 - eBPF XDP program at XDP ingress point (NIC driver or SKB generic)
//    2 - eBPF XDP program in program array slot
static int
check_xdp_running (int if_index, char * if_name)
{
	void	* ecbpf_ctx;
	int	err;
	char	progname[BPF_OBJ_NAME_LEN + 1];
	__u32	xdp_id = 0;


	// For NIC or SKB mode, simply supply interface index and check returns.
	if (!xdp_bypass_params_curr.mode_progarray) {
		err = bpf_xdp_query_id(if_index, xdp_flags, &xdp_id);
		if (!err && xdp_id)
			return 1;
		return 0;
	}

	// Determine if XDP kernel portion is in its program array slot already,
	// so check for occupancy as well as name.
	//
	// libecbpf calls need an ecbpf_ctx to be set up in order to use the
	// program array query, set up minimal amount needed to do query.
	ecbpf_ctx = ecbpf_ctx__new();
	if (!ecbpf_ctx) {
		printf("Unable to alloc libecbpf ctx to query prog array.\n");
		exit(EXIT_FAILURE);
	}

	if (ecbpf_ctx__set_interface(ecbpf_ctx, if_name)) {
		printf("Unable to set interface for prog array query.\n");
		exit(EXIT_FAILURE);
	}

	// Determine if program slot is occupied, just return if not.
	if (ecbpf__subprogram_slot_prog_id(ecbpf_ctx, xdp_prog_array_idx)
	<= 0) {
		ecbpf_ctx__free(ecbpf_ctx);
		return 0;
	}

	// Check for expected program name in this slot.
	memset(progname, '\0', sizeof(progname));
	err = ecbpf__subprogram_slot_name(ecbpf_ctx, xdp_prog_array_idx
	, progname, sizeof(progname));

	ecbpf_ctx__free(ecbpf_ctx);

	if (err) {
		printf("Unable to confirm prog array slot %d is xdp_bypass_ipvs"
		", assuming it is.\n", xdp_prog_array_idx);
		return 2;
	}

	if (!strstr(progname, "bypass_ipvs")) {
		printf("Prog array slot %d contains name %s instead of expected"
		" XDP bypass program.\n", xdp_prog_array_idx, progname);
		return 0;
	}
	return 2;
}

// check_xdp_running_all
//
// Invoke check_xdp_running() for all inbound (Internet) interfaces that
// need to have the XDP eBPF program running.
//
// Returns:
//     0 - At least one interface does not have "xdp" running.
//     1 - All interfaces running "xdp" in the same mode.
//     2 - All interfaces running "xdp" but in both program array & NIC modes.
static int
check_xdp_running_all (void)
{
	int	idx;
	interface_info_t * intfp;
	int	ret_status = -1;
	int	temp;

	for (idx = 1 ; idx < TC_MAX_LINKS; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex
		|| !(intfp->tc_info.if_flags & TC_INTF_F_INTERNET))
			continue;
		temp = check_xdp_running(intfp->ifindex, intfp->ifname);
		if (temp == 0)
			return 0;
		if (ret_status == -1)
			ret_status = temp;
		else if (ret_status != temp)
			return 2;
	}

	if (ret_status == -1)
		return 0;
	else
		return 1;
}

// detch_xdp_prog_all
//
// Remove all program array XDP inbound programs from each interface.
static void
detach_xdp_prog_all ()
{
	void	* ecbpf_ctx;
	int	idx;
	interface_info_t * intfp;

	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex
		|| !(intfp->tc_info.if_flags & TC_INTF_F_INTERNET))
			continue;
		ecbpf_ctx = ecbpf_ctx__new();
		if (!ecbpf_ctx) {
			printf("Unable to allocate libecbpf ctx to unload.\n");
			exit(EXIT_FAILURE);
		}
		if (ecbpf_ctx__set_interface(ecbpf_ctx, intfp->ifname)) {
			printf("Unexpected failure setting interface %s in "
			"ecbpf state.\n", intfp->ifname);
			exit(EXIT_FAILURE);
		}
		if (ecbpf__subprogram_detach(ecbpf_ctx, xdp_prog_array_idx)) {
			printf("Unable to remove XDP from program array on "
			"interface %s.\n", intfp->ifname);
		}
		ecbpf_ctx__free(ecbpf_ctx);
	}
}

// Display addresses which are not receiving "bypass" service.
static void
display_nobypass_addrs (char ** argv)
{
	int	count;
	__u32	inservice;
	__be32	v4addr;
	__be32	* v4addr_keyp;
	__be32	v4addr_nextkey;
	struct in6_addr	v6addr;
	struct in6_addr	* v6addr_keyp;
	struct in6_addr	v6addr_nextkey;

	// Dump any IPv4 addresses first, start with NULL first key to start.
	count = 0;
	v4addr_keyp = NULL;
	for (;;) {
		char	ipstr[INET_ADDRSTRLEN + 1];

		// Get next key to print out, or first one at loop start.
		if (bpf_map_get_next_key(mapinfo[MAP_IDX_V4LADDRS].mi_fd
		, v4addr_keyp, &v4addr_nextkey)) {
			// Assume at end of the addresses, possibly none.
			break;
		}

		// Set up for next key/pass through.
		v4addr_keyp = &v4addr;
		v4addr = v4addr_nextkey;

		// Fetch value of in-service flag.
		if (bpf_map_lookup_elem(mapinfo[MAP_IDX_V4LADDRS].mi_fd
		, &v4addr_nextkey, &inservice) < 0)
			continue;

		count++;
		if (count == 1)
			printf("\nIPv4 address(es) excluded from bypass.\n\n");

		(void)inet_ntop(AF_INET, (void *)v4addr_keyp
		, ipstr, sizeof(ipstr));
		printf("  %s %s\n", ipstr, inservice ? ""
		: "(non-configured interface)");
	}

	if (count)
		printf("\n\n");
	else
		printf("\n*** No IPv4 addresses excluded from bypass.\n\n\n");

	// Dump any IPv6 addresses, start with NULL first key to start.
	count = 0;
	v6addr_keyp = NULL;
	for (;;) {
		char	ip6str[INET6_ADDRSTRLEN + 1];

		// Get next key to print out, or first one at loop start.
		if (bpf_map_get_next_key(mapinfo[MAP_IDX_V6LADDRS].mi_fd
		, v6addr_keyp, &v6addr_nextkey)) {
			// Assume at end of the addresses, possibly none.
			break;
		}

		// Set up for next key/pass through.
		v6addr_keyp = &v6addr;
		v6addr = v6addr_nextkey;

		// Fetch value of in-service flag.
		if (bpf_map_lookup_elem(mapinfo[MAP_IDX_V6LADDRS].mi_fd
		, &v6addr_nextkey, &inservice) < 0)
			continue;

		count++;
		if (count == 1)
			printf("\nIPv6 address(es) excluded from bypass.\n\n");

		(void)inet_ntop(AF_INET6, (void *)v6addr_keyp
		, ip6str, sizeof(ip6str));
		printf("  %s %s\n", ip6str, inservice ? ""
		: "(non-configured interface)");
	}

	if (count)
		printf("\n\n");
	else
		printf("\n*** No IPv6 addresses excluded from bypass.\n\n\n");
}

// Display of parameters map was requested
static void
display_params_map (char ** argv)
{
	void	* ecbpf_ctx;
	int	err;
	int	idx;
	char	intf_names_tc[100];
	char	intf_names_xdp[100];
	interface_info_t * intfp;
	int	no_bpf_tc_xdp;
	__u32	proginfolen;
	int	tc_running = 0;
	char	* timestrp;
	char	vlan_hdr_tag_string[32];
	__u32	xdp_progid;
	struct bpf_prog_info xdp_proginfo;
	int	xdp_running = 0;

	// Get latest parameters, have already been pinned/verified by now.
	(void)read_current_params_map();

	// Re-validate VLAN field,  possibly corrupted pinned map.
	if (xdp_bypass_params_curr.vlan_hdr_tag >= -1
	&& xdp_bypass_params_curr.vlan_hdr_tag <= 4095) {
		(void)snprintf(vlan_hdr_tag_string, sizeof(vlan_hdr_tag_string)
		, "%d", xdp_bypass_params_curr.vlan_hdr_tag);
	} else {
		(void)snprintf(vlan_hdr_tag_string, sizeof(vlan_hdr_tag_string)
		, "(invalid, %d)", xdp_bypass_params_curr.vlan_hdr_tag);
	}

	// Status of eBPF components to add to output
	tc_running = check_tc_running_all(argv[0]);
	xdp_running = check_xdp_running_all();

	printf("\n");
	if (xdp_bypass_params_curr_pinned) {
		printf("Pinned maps version:\n  %s\n"
		, xdp_bypass_params_curr.map_header_sha256);
	}
	printf("Current code maps version:\n  %s\n"
	, XDP_BYPASS_IPVS_COMMON_H_SHA256);

	printf("\nCurrent parameters/settings:\n"
	"  nsecs before flow re-resolution: %llu (%d secs)\n"
	"  nsecs inbetween ipvs flow samples: %llu (%d secs)\n"
	"  monitor-only: %s\n"
	"  root program array mode: %s\n"
	"  limit inbound/outbound rates: %s\n"
	"  XDP_TX mode: %s\n"
	"  VLAN header tag: %s\n\n"
	"Rate limit settings:\n"
	"  RX CPUs: %u\n"
	"  RPS CPUs: %u\n"
	"  Inbound pps: %u\n"
	"  Inbound spike: %u%% (%'u)\n"
	"  Inbound max: %u%% (%'u)\n"
	"  Sample/Wrap count: %u\n"
	"  Max resets pps: %'u\n\n"
	"Calculated kernel/eBPF metrics from above:\n"
	"  RX CPU sample target inbound time (ns): %llu (%llu usecs)\n"
	"  RX CPU sample spike inbound time (ns): %llu (%llu usecs)\n"
	"  per-CPU (RPS) resets pps: %u\n\n"
	, xdp_bypass_params_curr.inactive_nsecs
	, (int)(xdp_bypass_params_curr.inactive_nsecs / NSECS_PER_SEC)
	, xdp_bypass_params_curr.sample_nsecs
	, (int)(xdp_bypass_params_curr.sample_nsecs / NSECS_PER_SEC)
	, xdp_bypass_params_curr.monitor_only ? "TRUE" : "FALSE"
	, xdp_bypass_params_curr.mode_progarray ? "TRUE" : "FALSE (NIC/SKB)"
	, xdp_bypass_params_curr.limit_rates ? "TRUE" : "FALSE"
	, xdp_bypass_params_curr.use_xdp_tx ? "TRUE" : "FALSE (redirect active)"

	, (xdp_bypass_params_curr.vlan_hdr_tag != -1 )
	? vlan_hdr_tag_string : "(none)"

	, xdp_bypass_params_curr.rx_cpus
	, xdp_bypass_params_curr.rps_cpus
	, xdp_bypass_params_curr.inbound_pps

	, xdp_bypass_params_curr.inbound_spike
	, (xdp_bypass_params_curr.inbound_pps
	* (100 + xdp_bypass_params_curr.inbound_spike)) / 100

	, xdp_bypass_params_curr.inbound_max
	, (xdp_bypass_params_curr.inbound_pps
	* (100 + xdp_bypass_params_curr.inbound_max)) / 100

	, xdp_bypass_params_curr.in_wrap_cnt
	, xdp_bypass_params_curr.max_reset_pps

	, xdp_bypass_params_curr.wrap_target_ns
	, xdp_bypass_params_curr.wrap_target_ns / 1000

	, xdp_bypass_params_curr.wrap_min_ns
	, xdp_bypass_params_curr.wrap_min_ns / 1000

	, xdp_bypass_params_curr.out_rsts * MAX_RESETS_EPOCH_DEF);

	// Probability display to confirm generated properly.
	printf("'Keep packet' probability (100%% -> <unlikely>) based on "
	"random byte <= to:\n ");
	for (idx = 0; idx < XBI_PARAMS_PROB_256; idx++)
		printf(" %d", xdp_bypass_params_curr.prob_256[idx]);
	printf("\n\n");

	// Gather interface names into strings for display, separated by
	// the tc_running (all interfaces) and xdp_running (inbound/Internet).
	// Flag interfaces with a "*" that aren't actually running either the
	// tc or xdp eBPF programs.
	intf_names_tc[0] = '\0';
	intf_names_xdp[0] = '\0';
	no_bpf_tc_xdp = 0;
	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex || !(intfp->tc_info.if_flags
		& (TC_INTF_F_INTERNET | TC_INTF_F_INSIDE)))
			continue;

		// Every interface into "tc" list, flag "*" if no "tc" loaded.
		if (intf_names_tc[0] != '\0') {
			(void)strncat(intf_names_tc, " "
			, sizeof(intf_names_tc) - strlen(intf_names_tc) - 1);
		}
		if (!check_tc_running(argv[0], intfp->ifname)) {
			no_bpf_tc_xdp++;
			(void)strncat(intf_names_tc, "*"
			, sizeof(intf_names_tc) - strlen(intf_names_tc) - 1);
		}
		(void)strncat(intf_names_tc, intfp->ifname
		, sizeof(intf_names_tc) - strlen(intf_names_tc) - 1);

		if (!(intfp->tc_info.if_flags & TC_INTF_F_INTERNET))
			continue;

		// All XDP interfaces, flag "*" if no "xdp" loaded.
		if (intf_names_xdp[0] != '\0') {
			(void)strncat(intf_names_xdp, " "
			, sizeof(intf_names_xdp) - strlen(intf_names_xdp) - 1);
		}
		if (!check_xdp_running(intfp->ifindex, intfp->ifname)) {
			no_bpf_tc_xdp++;
			(void)strncat(intf_names_xdp, "*"
			, sizeof(intf_names_xdp) - strlen(intf_names_xdp) - 1);
		}
		(void)strncat(intf_names_xdp, intfp->ifname
		, sizeof(intf_names_xdp) - strlen(intf_names_xdp) - 1);
	}

	printf("  tc (%s) eBPF running: %s\n"
	"  xdp (%s%s) eBPF running: %s\n"
	, intf_names_tc, tc_running ? "TRUE" : "FALSE"
	, xdp_bypass_params_curr.mode_progarray ? "program array, on: " : ""
	, intf_names_xdp, xdp_running ? "TRUE" : "FALSE");
	if (no_bpf_tc_xdp) {
		printf("(Interfaces marked with '*' are not running BPF tc "
		"or xdp code.)\n");
	}
	printf("\n");

	// Regardless of fastpath XDP code mode, attempt to display root name
	// for each inbound/Internet interface.   Also show the program array
	// slot info for fastpath, if that mode is configured.
	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex
		|| !(intfp->tc_info.if_flags & TC_INTF_F_INTERNET))
			continue;

		if (bpf_xdp_query_id(intfp->ifindex, xdp_flags, &xdp_progid)
		|| get_bpf_info(xdp_progid, &xdp_proginfo, &timestrp)) {
			// No program info nor time for this one.
			printf("  xdp (%s) running program name: %s\n"
			, intfp->ifname
			, "(not available, possibly iproute2-loaded?)");
		} else {
			printf("  xdp (%s) running program name: %s\n"
			, intfp->ifname
			, (xdp_proginfo.name[0] != '\0') ? xdp_proginfo.name
			: "(not available, possibly iproute2-loaded?)");
			printf("      Running since: %s", timestrp);
		}

		// Also display our program array name, if in that mode.
		if (xdp_running && xdp_bypass_params_curr.mode_progarray) {
			// Requires ecbpf context setup, for interface name.
			ecbpf_ctx = ecbpf_ctx__new();
			if (!ecbpf_ctx) {
				printf("Unable to alloc libecbpf ctx to query "
				"prog array in display parameters.\n");
				exit(EXIT_FAILURE);
			}

			if (ecbpf_ctx__set_interface(ecbpf_ctx
			, intfp->ifname)) {
				ecbpf_ctx__free(ecbpf_ctx);
				printf("Unable to set interface for prog array "
				"query in display parameters.\n");
				exit(EXIT_FAILURE);
			}

			// Get XDP program id in our slot.
			xdp_progid = ecbpf__subprogram_slot_prog_id(ecbpf_ctx
			, xdp_prog_array_idx);
			if (xdp_progid <= 0
			|| get_bpf_info(xdp_progid, &xdp_proginfo, &timestrp)) {
				// No program info nor time for this one.
				printf("  xdp (program array, on: %s) running "
				"program name: %s\n"
				, intfp->ifname
				, "(not available, reason unknown)");
			} else {
				printf("  xdp (program array, on: %s) running "
				"program name: %s\n"
				, intfp->ifname
				, (xdp_proginfo.name[0] != '\0')
				? xdp_proginfo.name
				: "(not available, reason unknown)");
				printf("      Running since: %s", timestrp);
			}

			ecbpf_ctx__free(ecbpf_ctx);
		}
		printf("\n");
	}
	printf("\n");
}

// Stats for inbound packet rates showing: total, average, min, and max rates.
// The packets discarded, along with the min and max discards, are also
// displayed.
// Reads in each per-CPU XDP inbound rate structure.
static void
display_stats_inbound_rates (void)
{
	__u64	curr_rate;
	struct timespec currtime;
	__u64	currtime_ns;
	uint	disc_max_cpu;
	__u64	disc_max_value = 0;
	uint	disc_min_cpu;
	__u64	disc_min_value = UINT_MAX;
	uint	idx;
	xdp_inbound_rates_t * in_ratep;
	xdp_inbound_rates_t * in_rate_allp;
	uint	num_cpus;
	uint	rate_max_cpu;
	uint	rate_max_value = 0;
	uint	rate_min_cpu;
	uint	rate_min_value = UINT_MAX;
	uint	rx_cpus;
	__u64	total_discards = 0;
	__u64	total_rate = 0;

	// Allocate memory for all possible per-CPU inbound rate structures.
	num_cpus = libbpf_num_possible_cpus();
	in_rate_allp = (xdp_inbound_rates_t *)malloc(num_cpus
	* sizeof(xdp_inbound_rates_t));
	if (!in_rate_allp) {
		printf("malloc: Unable to allocate %d CPUs of the %d bytes "
		"per-CPU inbound rates\n"
		, num_cpus, (int)sizeof(xdp_inbound_rates_t));
		return;
	}

	// Fetches all per-CPU inbound rates structures at once.
	memset(in_rate_allp, 0, (size_t)num_cpus * sizeof(xdp_inbound_rates_t));
	idx = 0;
	if (bpf_map_lookup_elem(mapinfo[MAP_IDX_IN_RATES].mi_fd, &idx
	, in_rate_allp)) {
		printf("\n\n*** Error fetching all per-CPU inbound rates, "
		"skipping. ***\n\n");
		free(in_rate_allp);
		return;
	}

	// Check each per-CPU inbound rate, track how many CPUs have RX values
	// reasonably close to the current time (within last 1/4 second).
	(void)clock_gettime(CLOCK_MONOTONIC, &currtime);
	currtime_ns = currtime.tv_sec * NSECS_PER_SEC
	+ currtime.tv_nsec - (NSECS_PER_SEC / 4);
	rx_cpus = 0;
	for (idx = 0 ; idx < num_cpus ; idx++) {
		in_ratep = in_rate_allp + idx;

		// Verify this CPU is currently receiving packets, has to
		// have wrapped the sample count recently.
		if (!in_ratep->last_wrap_ns
		|| in_ratep->ltime_wrap_ns < currtime_ns)
			continue;
		rx_cpus++;

		// Record min and max discard values.
		if (in_ratep->in_discards > disc_max_value) {
			disc_max_value = in_ratep->in_discards;
			disc_max_cpu = idx;
		}
		if (in_ratep->in_discards
		&& in_ratep->in_discards < disc_min_value) {
			disc_min_value = in_ratep->in_discards;
			disc_min_cpu = idx;
		}
		total_discards += in_ratep->in_discards;

		// Packet rate is calculated from the (last)wrap time in ns:
		//   (wrap pkts / wrap ns) * (1000000000 ns / 1 sec) -> pkts/sec
		// The terms are reordered to preserve integer precision.
		curr_rate = ((__u64)xdp_bypass_params_curr.in_wrap_cnt
		* NSECS_PER_SEC) / in_ratep->last_wrap_ns;

		if (curr_rate > rate_max_value) {
			rate_max_value = (uint)curr_rate;
			rate_max_cpu = idx;
		}
		if (curr_rate < rate_min_value) {
			rate_min_value = (uint)curr_rate;
			rate_min_cpu = idx;
		}
		total_rate += curr_rate;
	}

	if (rx_cpus == 0) {
		printf("\n*** No RX CPU stats, insufficient recent traffic? "
		"***\n\n");
		free(in_rate_allp);
		return;
	}
	if (rx_cpus != xdp_bypass_params_curr.rx_cpus) {
		printf("\n*** Warning: RX CPUs\' stats found does not match "
		"configured rx_cpus: ***\n"
		"***\t%d RX CPUs != %d RX CPUs from --cpus-rx-rps or default. "
		"***\n\n"
		, rx_cpus, xdp_bypass_params_curr.rx_cpus);
	}

	printf("\n"
	"Instantaneous inbound rate: %llupps  Average per-CPU rate: %llupps\n"
	"Min rate: %upps (CPU %d)  Max rate: %upps (CPU %d)\n\n"
	, total_rate, total_rate / (__u64)rx_cpus
	, rate_min_value, rate_min_cpu, rate_max_value, rate_max_cpu);

	if (total_discards) {
		printf( "Total inbound rate-limited discards: %llu\n"
		"Min discards: %llu (CPU %d)  Max discards: %llu (CPU %d)\n\n"
		, total_discards
		, disc_min_value, disc_min_cpu, disc_max_value, disc_max_cpu);
	} else
		printf("No inbound discards stats found\n\n");

	free(in_rate_allp);
}

// Stats are requested, display the 'cnt' sets requested at the specified 'secs'
// intervals from the stats pinned map.  Include a smattering of flows.
//
// Note: Errors are reported, but not fatal, in order to return to proceed
// with other functions such as unload/unpin.
static void
display_stats_maps (char ** argv, int secs, int cnt, int flows)
{
	int	num_cpus;
	xdp_global_stats_t	* stats_all_per_cpup;
	xdp_bypass_4tuple_t	tuple_key;
	xdp_bypass_4tuple_t *	tuple_keyp = NULL;
	xdp_bypass_4tuple_t	tuple_nextkey;
	xdp_bypass_dest_intf_t	tuple_value;

	/*
	 * Allocate memory for all the PER_CPU stats we need, the function
	 * libbpf_num_possible_cpus() is not really dynamic but MUST be the
	 * max possible.  This is due to the bpf lookup interface not allowing
	 * the specification of the supplied buffer, so must always be the
	 * largest.   There is also no indication of the returned # of CPUs'
	 * data so the area would have to be zeroed before each lookup.
	 */
	num_cpus = libbpf_num_possible_cpus();
	stats_all_per_cpup = (xdp_global_stats_t *)malloc(num_cpus
	* sizeof(xdp_global_stats_t));
	if (!stats_all_per_cpup) {
		printf("malloc: Unable to allocate %d CPUs of the %d bytes "
		"PER_CPU stats\n", num_cpus, (int)sizeof(xdp_global_stats_t));
		return;
	}

	// Stats loop for specified cnt, optionally display (some) flows too.
	for (; cnt-- ;) {
		int	count;
		time_t	currtime;
		long	fwm_count;
		int	fwm_idx;
		int	stats_idx;

		// Sleep first, can load and delay for first stats set.
		sleep(secs);

		(void)time(&currtime);
		printf("\n%s\n", ctime(&currtime));
		fflush(stdout);

		/*
		 * Special check to see if XDP/tc eBPF are processing.  This
		 * is looking at the zero firewall mark having a -1 counter.
		 */
		fwm_idx = 0;
		fwm_count = 0;
		bpf_map_lookup_elem(mapinfo[MAP_IDX_FWM].mi_fd, &fwm_idx
		, &fwm_count);
		if (fwm_count == -1) {
			printf("\n\n**** XDP/tc eBPF unable to process "
			"packets, exiting. ****\n\n");
			return;
		}

		/* FWM (FireWall Mark) map is array of total flow counts. */
		if (flows) {
			printf("\n\nFWM\tTotal\n\n");

			for (fwm_idx = 0; fwm_idx < 256 ; fwm_idx++) {

				fwm_count = 0;
				bpf_map_lookup_elem(mapinfo[MAP_IDX_FWM].mi_fd
				, &fwm_idx, &fwm_count);
				if (!fwm_count)
					continue;
				printf("%d\t%lu\n", fwm_idx, fwm_count);
			}
		}

		/* Tuples map for bypass flows with # eBPF packets bypassed. */
		count = 0;
		while (flows && count < 20) {
			char	dststr[INET_ADDRSTRLEN + 1];
			char	srcstr[INET_ADDRSTRLEN + 1];

			if (bpf_map_get_next_key(mapinfo[MAP_IDX_TUPLES].mi_fd
			, tuple_keyp, &tuple_nextkey)) {
				/* Restart from the beginning, if at end. */
				if (tuple_keyp)
					tuple_keyp = NULL;
				break;
			}

			tuple_keyp = &tuple_key;
			memcpy(&tuple_key, &tuple_nextkey, sizeof(tuple_key));
			memset(&tuple_value, 0, sizeof(tuple_value));
			count++;

			/* Fetch key, possible LRU-collection "race". */
			if (bpf_map_lookup_elem(mapinfo[MAP_IDX_TUPLES].mi_fd
			, &tuple_nextkey, &tuple_value) < 0)
				continue;

			if (count == 1) {
				printf("\nSampling of flows\n");
				printf("\n\nraddr[rport]->"
				"laddr[lport]    MAC addrs  "
				"bypass outbound   CPU   "
				"Res  Res_Delay\n\n");
			}

			(void)inet_ntop(tuple_nextkey.family
			, (void *)&tuple_nextkey.raddr, srcstr, sizeof(srcstr));
			(void)inet_ntop(tuple_nextkey.family
			, (void *)&tuple_nextkey.laddr, dststr, sizeof(dststr));

			printf("%s[%d]->%s[%d]   "
			"%02x:%02x:%02x:%02x:%02x:%02x->"
			"%02x:%02x:%02x:%02x:%02x:%02x %lu %lu %d %d %d\n"
			, srcstr, ntohs(tuple_nextkey.rport)
			, dststr, ntohs(tuple_nextkey.lport)
			, tuple_value.eth_saddr[0], tuple_value.eth_saddr[1]
			, tuple_value.eth_saddr[2], tuple_value.eth_saddr[3]
			, tuple_value.eth_saddr[4], tuple_value.eth_saddr[5]
			, tuple_value.eth_daddr[0], tuple_value.eth_daddr[1]
			, tuple_value.eth_daddr[2], tuple_value.eth_daddr[3]
			, tuple_value.eth_daddr[4], tuple_value.eth_daddr[5]
			, tuple_value.pkts_bypass, tuple_value.pkts_outbound
			, tuple_value.creation_cpu
			, tuple_value.resolved, tuple_value.resolve_delay);
		}

		// Global stats summary, fetch all PER_CPU stats structures.
		memset(stats_all_per_cpup, 0
		, (size_t)num_cpus * sizeof(xdp_global_stats_t));
		stats_idx = 0;
		if (bpf_map_lookup_elem(mapinfo[MAP_IDX_STATS].mi_fd, &stats_idx
		, stats_all_per_cpup)) {
			printf("\n\n*** Error fetching all PER_CPU stats, "
			"skipping. ***\n\n");
		} else {
			int	cpu_idx;
			int	field_idx;
			__u64	* field_cpup;
			__u64	* field_totalp;
			xdp_global_stats_t stats_totals;

			printf("\n Global stats\n\n");
			memset((void *)&stats_totals, 0
			, sizeof(xdp_global_stats_t));

			/* Sum each CPU's stats into one total structure. */
			field_totalp = (__u64 *)&stats_totals;
			for (cpu_idx = 0; cpu_idx < num_cpus ; cpu_idx++) {
				field_cpup = (__u64 *)
				&stats_all_per_cpup[cpu_idx];

#define NUM_FIELDS (sizeof(xdp_global_stats_t) / sizeof(__u64))
				for (field_idx = 0
				; field_idx < NUM_FIELDS
				; field_idx++) {
					field_totalp[field_idx]
					+= field_cpup[field_idx];
				}
			}

			/* Other than first few, only print non-zero totals. */
			printf("total_pkts_xdp_rx: %llu\n"
			, stats_totals.total_pkts_xdp_rx);
			printf("total_pkts_tc_tx: %llu\n"
			, stats_totals.total_pkts_tc_tx);
			printf("total_bypassed_pkts: %llu\n"
			, stats_totals.total_bypassed_pkts);
			printf("lru_alloc_map_tuples (not reduced for LRU clean"
			" ups): %llu\n"
			, stats_totals.lru_alloc_map_tuples);
			if (stats_totals.lru_fail_map_tuples) {
				printf("lru_fail_map_tuples: %llu\n"
				, stats_totals.lru_fail_map_tuples);
			}
			printf("ipv4_pkts: %llu\n", stats_totals.ipv4_pkts);
			printf("ipv6_pkts: %llu\n", stats_totals.ipv6_pkts);
			printf("tcp_pkts: %llu\n", stats_totals.tcp_pkts);
			printf("broad_multi_pkts: %llu\n"
			, stats_totals.broad_multi_pkts);
			printf("lru_alloc_syns: %llu\n"
			, stats_totals.lru_alloc_syns);
			printf("lru_reuse_syns: %llu\n"
			, stats_totals.lru_reuse_syns);

			if (stats_totals.ipv4_inbound_locals) {
				printf("ipv4_inbound_locals: %llu\n"
				, stats_totals.ipv4_inbound_locals);
			}
			if (stats_totals.ipv6_inbound_locals) {
				printf("ipv6_inbound_locals: %llu\n"
				, stats_totals.ipv6_inbound_locals);
			}
			if (stats_totals.suspect_misflows_sack) {
				printf("suspect_misflows_sack: %llu\n"
				, stats_totals.suspect_misflows_sack);
			}
			if (stats_totals.unexpected_ipvs_rsts) {
				printf("unexpected_ipvs_rsts: %llu\n"
				, stats_totals.unexpected_ipvs_rsts);
			}
			if (stats_totals.lru_deletion_RST) {
				printf("lru_deletion_RST: %llu\n"
				, stats_totals.lru_deletion_RST);
			}
			if (stats_totals.lru_deletion_out_RST) {
				printf("lru_deletion_out_RST: %llu\n"
				, stats_totals.lru_deletion_out_RST);
			}
			if (stats_totals.lru_alloc_nonsyns) {
				printf("lru_alloc_nonsyns: %llu\n"
				, stats_totals.lru_alloc_nonsyns);
			}
			if (stats_totals.lru_reuse_nonsyns) {
				printf("lru_reuse_nonsyns: %llu\n"
				, stats_totals.lru_reuse_nonsyns);
			}
			if (stats_totals.lru_miss_out_syn) {
				printf("lru_miss_out_syn: %llu\n"
				, stats_totals.lru_miss_out_syn);
			}
			if (stats_totals.lru_miss_out_nonsyn) {
				printf("lru_miss_out_nonsyn: %llu\n"
				, stats_totals.lru_miss_out_nonsyn);
			}
			if (stats_totals.lru_miss_in_limited) {
				printf("lru_miss_in_limited: %llu\n"
				, stats_totals.lru_miss_in_limited);
			}
			if (stats_totals.out_rsts_sent_tc) {
				printf("out_rsts_sent_tc: %llu\n"
				, stats_totals.out_rsts_sent_tc);
			}
			if (stats_totals.out_rsts_sent_xdp) {
				printf("out_rsts_sent_xdp: %llu\n"
				, stats_totals.out_rsts_sent_xdp);
			}
			if (stats_totals.out_rsts_disc_rate) {
				printf("out_rsts_disc_rate: %llu\n"
				, stats_totals.out_rsts_disc_rate);
			}
			if (stats_totals.out_rsts_disc_flow) {
				printf("out_rsts_disc_flow: %llu\n"
				, stats_totals.out_rsts_disc_flow);
			}
			if (stats_totals.out_rsts_unknown) {
				printf("out_rsts_unknown: %llu\n"
				, stats_totals.out_rsts_unknown);
			}
			if (stats_totals.in_rsts_disc_flow) {
				printf("in_rsts_disc_flow: %llu\n"
				, stats_totals.in_rsts_disc_flow);
			}
			if (stats_totals.resolution_pending) {
				printf("resolution_pending: %llu\n"
				, stats_totals.resolution_pending);
			}
			if (stats_totals.inactivity_timeout) {
				printf("inactivity_timeout: %llu\n"
				, stats_totals.inactivity_timeout);
			}
			if (stats_totals.lru_res_delayed) {
				printf("lru_res_delayed: %llu\n"
				, stats_totals.lru_res_delayed);
			}
			if (stats_totals.lru_res_delayed_fixed) {
				printf("lru_res_delayed_fixed: %llu\n"
				, stats_totals.lru_res_delayed_fixed);
			}
			if (stats_totals.lru_res_reuse_fix) {
				printf("lru_res_reuse_fix: %llu\n"
				, stats_totals.lru_res_reuse_fix);
			}
			if (stats_totals.resolution_drops) {
				printf("resolution_drops: %llu\n"
				, stats_totals.resolution_drops);
			}
			if (stats_totals.resolution_failed) {
				printf("resolution_failed: %llu\n"
				, stats_totals.resolution_failed);
			}
			if (stats_totals.ipv4_fragmented_pkts) {
				printf("ipv4_fragmented_pkts: %llu\n"
				, stats_totals.ipv4_fragmented_pkts);
			}
			if (stats_totals.ipv4_outbound_local_marked) {
				printf("ipv4_outbound_local_marked: %llu\n"
				, stats_totals.ipv4_outbound_local_marked);
			}
			if (stats_totals.frame_errors) {
				printf("frame_errors: %llu\n"
				, stats_totals.frame_errors);
			}
			if (stats_totals.adjust_head_errors) {
				printf("bpf_xdp_adjust_head_errors: %llu\n"
				, stats_totals.adjust_head_errors);
			}

			display_stats_inbound_rates();
		}
	}
}


// Helper to wrap libecbpf call to log stats to statsd/collectd
static void
statsd_send_gauge (char * metric_name, __u64 value) {
	int res, backoff;
	static int failures;
	char metric[4096];

	snprintf(metric, sizeof metric, "bypass_ipvs.%s", metric_name);

	res = ecbpf_log_statsd_gauge(LIBECBPF_STATSD_HOST, LIBECBPF_STATSD_PORT, metric, value);
	if (res) {
		if ((1 << failures) < LIBECBPF_STATSD_MAX_BACKOFF) {
			backoff = 1 << failures;
			failures++;
		} else {
			backoff = LIBECBPF_STATSD_MAX_BACKOFF;
		}
		fprintf(stderr, "statsd_send_gauge: ecbpf_log_statsd_gauge call failed: %i: Sleeping for %i seconds\n", res, backoff);
		sleep(backoff);
	} else {
		failures = 0;
	}
}

// Send a subset of the global stats off to statsd
//
// Note: Errors are reported, but not fatal, in order to return to proceed
// with other functions such as unload/unpin.
static void
statsd_stats_maps (char ** argv)
{
	int	num_cpus;
	xdp_global_stats_t	* stats_all_per_cpup;

	/*
	 * Allocate memory for all the PER_CPU stats we need, the function
	 * libbpf_num_possible_cpus() is not really dynamic but MUST be the
	 * max possible.  This is due to the bpf lookup interface not allowing
	 * the specification of the supplied buffer, so must always be the
	 * largest.   There is also no indication of the returned # of CPUs'
	 * data so the area would have to be zeroed before each lookup.
	 */
	num_cpus = libbpf_num_possible_cpus();
	stats_all_per_cpup = (xdp_global_stats_t *)malloc(num_cpus
	* sizeof(xdp_global_stats_t));
	if (!stats_all_per_cpup) {
		printf("malloc: Unable to allocate %d CPUs of the %d bytes "
		"PER_CPU stats\n", num_cpus, (int)sizeof(xdp_global_stats_t));
		return;
	}

	// Loop forever to send stats to collectd
	for (;;) {
		int	count;
		time_t	currtime;
		long	fwm_count;
		int	fwm_idx;
		int	stats_idx;

		// Sleep first, can load and delay for first stats set.
		sleep(1);

		/*
		 * Special check to see if XDP/tc eBPF are processing.  This
		 * is looking at the zero firewall mark having a -1 counter.
		 */
		fwm_idx = 0;
		fwm_count = 0;
		bpf_map_lookup_elem(mapinfo[MAP_IDX_FWM].mi_fd, &fwm_idx
		, &fwm_count);
		if (fwm_count == -1) {
			printf("\n\n**** XDP/tc eBPF unable to process "
			"packets, exiting. ****\n\n");
			return;
		}

		// Global stats summary, fetch all PER_CPU stats structures.
		memset(stats_all_per_cpup, 0
		, (size_t)num_cpus * sizeof(xdp_global_stats_t));
		stats_idx = 0;
		if (bpf_map_lookup_elem(mapinfo[MAP_IDX_STATS].mi_fd, &stats_idx
		, stats_all_per_cpup)) {
			printf("\n\n*** Error fetching all PER_CPU stats, "
			"skipping reporting to collectd, exiting. ***\n\n");
			return;
		} else {
			int	cpu_idx;
			int	field_idx;
			__u64	* field_cpup;
			__u64	* field_totalp;
			xdp_global_stats_t stats_totals;

			memset((void *)&stats_totals, 0
			, sizeof(xdp_global_stats_t));

			/* Sum each CPU's stats into one total structure. */
			field_totalp = (__u64 *)&stats_totals;
			for (cpu_idx = 0; cpu_idx < num_cpus ; cpu_idx++) {
				field_cpup = (__u64 *)
				&stats_all_per_cpup[cpu_idx];

				for (field_idx = 0
				; field_idx < NUM_FIELDS
				; field_idx++) {
					field_totalp[field_idx]
					+= field_cpup[field_idx];
				}
			}

			/* Other than first few, only print non-zero totals. */
			statsd_send_gauge("total_pkts_xdp_rx"
			, stats_totals.total_pkts_xdp_rx);
			statsd_send_gauge("total_bypassed_pkts"
			, stats_totals.total_bypassed_pkts);

			if (stats_totals.out_rsts_sent_tc) {
				statsd_send_gauge("out_rsts_sent_tc"
				, stats_totals.out_rsts_sent_tc);
			}
			if (stats_totals.out_rsts_sent_xdp) {
				statsd_send_gauge("out_rsts_sent_xdp"
				, stats_totals.out_rsts_sent_xdp);
			}
			if (stats_totals.out_rsts_unknown) {
				statsd_send_gauge("out_rsts_unknown"
				, stats_totals.out_rsts_unknown);
			}
		}
	}
}

// Fetch bpf program info from program id & printable load time.
// Return 0 on success, otherwise an error.
static int
get_bpf_info (int prog_id, struct bpf_prog_info * infop, char ** timestrp)
{
	int	prog_fd;
	__u32	proginfolen;
	time_t	time_loaded;
	struct timespec timespec;

	// Get file handle from BPF program id.
	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd <= 0) {
		printf("File handle failure on BPF prog id %d, error: (%d) %s\n"
		, prog_id, errno, strerror(errno));
		return EINVAL;
	}

	// Note: bpf_prog_info expanded after 4.15 kernel, so all additional
	// fields must be pre-zeroed and post-call only fields common to all
	// versions may be used without checking for validity.
	proginfolen = sizeof(struct bpf_prog_info);
	memset(infop, 0, proginfolen);
	if (bpf_obj_get_info_by_fd(prog_fd, infop, &proginfolen)) {
		close(prog_fd);
		printf("Unable to get BPF program info for prog id %d, "
		"error: (%d) %s\n", prog_id, errno, strerror(errno));
		return EINVAL;
	}
	close(prog_fd);

	// Get current time in Epoch seconds, subtract time since boot, add back
	// in load time after boot.  Ignore higher-precision micro or
	// nano seconds.
	clock_gettime(CLOCK_REALTIME, &timespec);
	time_loaded = timespec.tv_sec;
	clock_gettime(CLOCK_BOOTTIME, &timespec);
	time_loaded -= timespec.tv_sec;
	time_loaded += (infop->load_time / NSECS_PER_SEC);

	*timestrp = ctime(&time_loaded);
	return 0;
}

static int
get_hw_ifaddr (char * ifname, int ifindex, unsigned char * hwaddr, int hwlen)
{
	int	fd;
	struct ifreq	ifreq;
	struct sockaddr_ll	if_socket;

	/* Raw socket for interface access, use unlikely packet type. */
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_SNAP));
        if (fd < 0) {
                perror("socket for interface name");
		return -1;
        }

	/* Prepare to bind to something unlikely to attract packets. */
	if_socket.sll_protocol = __bswap_constant_16(ETH_P_SNAP);
	if_socket.sll_family = AF_PACKET;
	if_socket.sll_halen = ETH_ALEN;
	if_socket.sll_ifindex = ifindex;

	if (bind(fd, (const struct sockaddr *)&if_socket, sizeof(if_socket))) {
		perror("bind() ifindex");
		return -1;
        }

	/* Get hardware MAC address by name. */
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFHWADDR, (char *)&ifreq)) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
	}
	memcpy((void *)hwaddr, (void *)ifreq.ifr_hwaddr.sa_data, hwlen);
	return 0;
}

// init_from_intf_map()
//
// Initialize the local copy of interfaces maps taking the results
// of the command line parsing and merging in the pinned maps' data, if any.
// This is only required for commands other than (un)load, since (un)load
// requires full interface specification.
//
// This function can only be invoked after all pinned maps are opened.
// TOCONSIDER: Allow changing -i, -o, options for non-(Un)load commands,
// thus doing interface-specific (un)load operations.
static void
init_from_intf_map ()
{
	int	idx;
	interface_info_t temp_intf;

	// Load/unload nothing to do, maps will be rewritten from command
	// line options specified.
	if (load_flag || (unload_flag && ifinputcnt && ifoutputcnt))
		return;

	// Walk through interfaces recorded in pinned map, if any, and add
	// into the command line interfaces array that have no corresponding
	// entry.
	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++ ) {
		// Skip non-existent or deleted interfaces.
		if (bpf_map_lookup_elem(mapinfo[MAP_IDX_INTERFACES].mi_fd
		, &idx, &temp_intf.tc_info) < 0
		|| temp_intf.tc_info.if_flags == 0)
			continue;

		// For "bypass" address interfaces that are not in the latest
		// explicit request, skip them.
		if (ifaddrscnt
		&& temp_intf.tc_info.if_flags == TC_INTF_F_BYPASS
		&& !interface_info[idx].ifindex)
			continue;

		// Merge in new address info or elide old.
		if (interface_info[idx].ifindex
		&& (interface_info[idx].tc_info.if_flags & TC_INTF_F_BYPASS))
			temp_intf.tc_info.if_flags |= TC_INTF_F_BYPASS;
		else
			temp_intf.tc_info.if_flags &= ~TC_INTF_F_BYPASS;

		temp_intf.ifname = (char *)malloc(IF_NAMESIZE);
		if (!if_indextoname(idx, temp_intf.ifname)) {
			printf("\n*** Invalid if index: %d ignored "
			"in pinned interfaces map. ***\n\n"
			, idx);
			free(temp_intf.ifname);
			continue;
		}
		temp_intf.ifindex = idx;
		interface_info[idx] = temp_intf;
	}
}

static void
load_current_tc_xdp (char ** argv, int force_flag)
{
	char	bpf_tc_fname[MAX_FILENAME];
	char	bpf_xdp_fname[MAX_FILENAME];
	char	* cmdnamep;
	char	* cmdpathp;
	int	cnt;
	int	err;
	int	idx;
	int	progarray_change;
	int	tc_running = 0;
	int	version_match;
	int	xdp_running;

	// Get base command name for objects.
	cmdpathp = strdup(argv[0]);
	if (!cmdpathp || !(cmdnamep = basename(cmdpathp))) {
		printf("\n*** Allocation failure for loading objects. ***\n\n");
		exit(EXIT_FAILURE);
	}

	// There are separate XDP and TC eBPF kernel .o files.
	if (kernel_objs_path) {
		snprintf(bpf_xdp_fname, sizeof(bpf_xdp_fname)
		, "%s/%s_xdp_kern.o", kernel_objs_path, cmdnamep);
		snprintf(bpf_tc_fname, sizeof(bpf_tc_fname), "%s/%s_tc_kern.o"
		, kernel_objs_path, cmdnamep);
	} else {
		snprintf(bpf_xdp_fname, sizeof(bpf_xdp_fname), "%s_xdp_kern.o"
		, cmdnamep);
		snprintf(bpf_tc_fname, sizeof(bpf_tc_fname), "%s_tc_kern.o"
		, cmdnamep);
	}
	bpf_xdp_fname[sizeof(bpf_xdp_fname) - 1] = '\0';
	bpf_tc_fname[sizeof(bpf_tc_fname) - 1] = '\0';

	free(cmdpathp);

	// Get maps opened so we can see/use currently-pinned version.   If this
	// fails for ENOENT then just proceed with loading both "tc" and "xdp"
	// programs since we can start with fresh maps.
	err = open_pinned_maps(argv, 0);
	if (err) {
		if (err != ENOENT) {
			printf("Load can not proceed due to error above.\n");
			exit(EXIT_FAILURE);
		}

		// Maps apparently do not exist, need latest "tc" loaded
		// Supply tc kernel object name.
		// This sets up "tc" eBPF on all interfaces.
		replace_tc_bpf_all(bpf_tc_fname);
		(void)open_pinned_maps(argv, 1);

		// "tc" just loaded successfully or maps ok now (somehow).
		tc_running = 1;
	}

	// Maps are all available/pinned, will need copy of parameters.
	err = read_current_params_map();
	if (err) {
		printf("Unexpected failure (%d)' %s' reading version "
		"from map: %s\n", err, strerror(err)
		, mapinfo[MAP_IDX_PARAMS].mi_name);
		exit(EXIT_FAILURE);
	}

	// XDP and TC eBPF status for the following decision paths.
	if (!tc_running) {
		// Not explicitly set above, need to determine.
		tc_running = check_tc_running_all(bpf_tc_fname);
	}
	xdp_running = check_xdp_running_all();

	// For same version of maps, reload tc and xdp code if they don't both
	// appear to be running.   This accepts, automatically, that there may
	// be stale state in the same-version maps.  And no disruption will
	// occur since the code is not fully configured.   The code is expected
	// to handle old flows, by re-resolving.  Otherwise, if both tcp and xdp
	// are running only overwrite with the new code if the "force" flag has
	// been set to accept possible flow disruptions even though state is
	// current.   This is likely a common operation, such as fixing code but
	// the map structures stayed the same so session state remains intact
	// across code instances.
	//
	// If maps are NOT the same version then the "force" flag is needed in
	// any case to reload any state of running configuration.  If maps are
	// known to be compatible then an already running configuration can be
	// reloaded using the existing maps (with minor disruption) ; or to use
	// existing stale maps if not running.
	//
	// If the "force" flag is not set then the non-matching version will
	// always cause an exit, with a message that suggests doing a full
	// unload first so both maps and code can be re-restablished fresh.
	version_match = !memcmp(XDP_BYPASS_IPVS_COMMON_H_SHA256
	, xdp_bypass_params_curr.map_header_sha256
	, sizeof(XDP_BYPASS_IPVS_COMMON_H_SHA256));
	progarray_change = (mode_progarray_flag
	&& xdp_bypass_params_curr.mode_progarray
	!= xdp_bypass_params.mode_progarray
	&& xdp_running) ? 1 : 0;

	if (!progarray_change
	&& ((version_match && ((tc_running && xdp_running && force_flag)
	|| (!tc_running || !xdp_running)))  // Preceding are the "match" cases
	|| (!version_match && force_flag))) {
		// In all these cases, code is being (re)loaded and the
		// parameters are updated just before the XDP portion is
		// (re)loaded so proper rate limits are set up.
		// Note that "tc" may not actually be (re)loaded here, since
		// it may have been loaded above to get the maps initialized.
		replace_tc_bpf_all(bpf_tc_fname);
		update_params_addrs_maps();
	      	replace_xdp_bpf_all(bpf_xdp_fname);
	} else {
		printf("Load operation aborted.  Possible reasons are:\n"
		"  Missing -F (force) option with mismatched map versions.\n"
		"  eBPF programs already loaded and maps match, -F needed for "
		"minor disruption.\n"
		"  Change in -p setting, requires a -U (unload) first.\n\n"
		"For mismatched maps a -U (unload) may be needed/appropriate "
		"first\nto avoid runtime errors.\n\n"
		"Various parameters used in this decision:\n"
		"  -F (force): %s\n"
		, force_flag ? "TRUE" : "FALSE");

		// Rest of the info comes from standard paramaters display.
		display_params_map(argv);
		exit(EXIT_FAILURE);
	}
}

// Load up current directory's "nop_kern.o" XDP program to overwrite the
// main XDP program, so as to not disrupt/reinitialize driver rings.
//
// This function is part of a termination/unpin/cleanup so any errors
// are ignored, other than those that prevent continuing.
static void
load_current_nop_xdp (int if_index)
{
	char	bpf_filename[MAX_FILENAME];
	int	err;
	struct bpf_object * kern_bpf_objs;
	struct bpf_program * kern_bpf_prog;
	int	nop_prog_fd;
	libbpf_print_fn_t prior_print_fn = NULL;

	// Replace inbound XDP with nop_kern.o in objects directory.
	// Make full pathname, open/fetch BPF objects, find the
	// program section to set attributes, load it, and obtain
	// file descriptor for replacing on the NIC.
	if (kernel_objs_path) {
		snprintf(bpf_filename, sizeof(bpf_filename), "%s/nop_kern.o"
		, kernel_objs_path);
	} else
		snprintf(bpf_filename, sizeof(bpf_filename), "nop_kern.o");
	bpf_filename[sizeof(bpf_filename) - 1] = '\0';

	kern_bpf_objs = bpf_object__open_file(bpf_filename, NULL);
	err = libbpf_get_error(kern_bpf_objs);
	if (err) {
		printf("Error doing bpf_object__open_file of %s\n  error: (%d) %s\n"
		, bpf_filename, err, strerror(err));
		return;
	}

	err = bpf_object__load(kern_bpf_objs);
	if (err) {
		printf("Error doing bpf_prog_load of %s\n  error: (%d) %s\n"
		, bpf_filename, err, strerror(err));
		return;
	}

	kern_bpf_prog = bpf_object__next_program(kern_bpf_objs, NULL);
	if (! kern_bpf_prog) {
		printf("Error doing bpf_program__next of %s\n"
		, bpf_filename);
		return;
	}

	nop_prog_fd = bpf_program__fd(kern_bpf_prog);
	if (nop_prog_fd < 0) {
		err = -nop_prog_fd;
		printf("Error doing bpf_program__fd of %s\n  error: (%d) %s\n"
		, bpf_filename, err, strerror(err));
		return;
	}

	bpf_xdp_attach(if_index, nop_prog_fd, xdp_flags, NULL);
}

// load_current_nop_xdp_all
//
// Invokes load_current_nop_xdp for each interface to replace either the
// XDP eBPF input program or dummy program with the NOP XDP program.
static void
load_current_nop_xdp_all (void)
{
	int	idx;
	interface_info_t * intfp;

	for (idx = 1 ; idx < TC_MAX_LINKS; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex)
			continue;
		load_current_nop_xdp(intfp->ifindex);
	}
	xdp_loaded = 0;
}

// If not already done, open file descriptor for each map that SHOULD have been
// already-pinned by "tc" insertion of eBPF "egress" function
//
// Either exits on error, if 'exit_on_error' specified, or returns:
// 0 - success, all pinned maps opened.
// (errno) - if error encountered, any maps opened are closed.
static int
open_pinned_maps (char ** argv, int exit_on_error)
{
	int	cnt;
	int	idx;
	char	map_path[PATH_MAX];
	int	pin_map_fd;

	if (mapinfo_init)
		return 0;

	// Maps should exist, at least the tc that pinned them must have run
	for (idx = 0 ; idx < sizeof(mapinfo)/sizeof(mapinfo[0]) ; idx++) {
		// Confirm pinned map exists by opening and getting file handle
		cnt = snprintf(map_path, sizeof(map_path), "%s/%s"
		, TC_GLOBAL_MAPS_PATH, mapinfo[idx].mi_name);
		if (cnt < 0 || cnt >= sizeof(map_path)) {
			// Report this error, regardless of exit mode.
			printf("map_path %s/%s overrun or output error of: "
			"%d\n", TC_GLOBAL_MAPS_PATH, mapinfo[idx].mi_name, cnt);
			exit(EXIT_FAILURE);
		}

		pin_map_fd = bpf_obj_get(map_path);
		if (pin_map_fd < 0) {
			if (!exit_on_error)
				goto error_exit;
			printf("Open error on pinned map: %s\n error: (%d) %s\n"
			, map_path, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		mapinfo[idx].mi_fd = pin_map_fd;
	}

	mapinfo_init = 1;
	return 0;

error_exit:;
	while (idx >= 0) {
		// Skip closing parameters map, if opened, for clean up.
		if (idx != MAP_IDX_PARAMS && mapinfo[idx].mi_fd != 0) {
			close(mapinfo[idx].mi_fd);
			mapinfo[idx].mi_fd = 0;
		}
		--idx;
	}
	return errno;
}

// Read current parameters map
//
// Returns:
//   0 - Current parameters read or initialized, may not be pinned/written yet.
// (errno) - Unexpected error reading pinned map
static int
read_current_params_map ()
{
	int	err;
	int	idx;

	if (xdp_bypass_params_curr_pinned)
		return 0;

	idx = 0;
	err = bpf_map_lookup_elem(mapinfo[MAP_IDX_PARAMS].mi_fd, &idx
	, &xdp_bypass_params_curr);
	// Initialize current parameters map if entry missing or if has an
	// all-zeroes sha256 (presumably due to "tc" just loaded?).
	if (err || !memcmp(xdp_bypass_params_default.map_header_sha256
	, xdp_bypass_params_curr.map_header_sha256
	, sizeof(xdp_bypass_params_curr.map_header_sha256))) {
       		if (err && errno != ENOENT)
			return errno;
		// Initialize current, using any specified updates + defaults
		memcpy((void *)&xdp_bypass_params_curr
		, (void *)&xdp_bypass_params
		, sizeof(xdp_bypass_params_curr));
		memcpy(xdp_bypass_params_curr.map_header_sha256
		, XDP_BYPASS_IPVS_COMMON_H_SHA256
		, sizeof(XDP_BYPASS_IPVS_COMMON_H_SHA256));
		// Explicit indication that current pinned needs updating
		xdp_bypass_params_curr_pinned = 0;
		return 0;
	}

	xdp_bypass_params_curr_pinned = 1;
	return 0;
}


/*
 * Replace or install BPF program at specified interface name.
 *
 * There is a dependency on use of "tc" to load the traffic control
 * eBPF egress hook at the appropriate "out" interface to snoop on
 * ipvs server selections.   It must be loaded first so that incoming
 * packets on the "in" interface don't get "black holed".
 * Further, it is assumed that the "tc" process will pin
 * the data maps in the tc globals map space using tc's built in loading
 * process that requires especially "marked" eBPF maps that have extra
 * fields on the trailing end (see kernel object(s)).
 *
 * The tc eBPF egress hook is also installed on the incoming (Internet)
 * interface in order to rate-control/limit outbound RSTs as well as flag
 * specific TCP flows as being reset.
 */
static void
replace_tc_bpf (char * bpf_filename, char * ifname)
{
	int	cnt;
	int	err;
	int	err_status;
	char	tc_cmdbuf[MAX_FILENAME + 100];

	// In case system was just booted or previous "tc" qdisc unloaded the
	// "clsact" qdisc can be safely (re)installed so that the needed
	// tc "egress" hook is available for the eBPF program that will be
	// loaded next.  "clsact" is a dummy qdisc that just provides the
	// needed callouts for eBPF packet classification/action, it does no
	// actual queueing.
	cnt = snprintf(tc_cmdbuf, sizeof(tc_cmdbuf)
	, "tc qdisc replace dev %s clsact", ifname);
	if (cnt < 0 || cnt >= sizeof(tc_cmdbuf)) {
		printf("Unable to set up 'tc' command to load clsact qdisc for "
		"egress eBPF, command length overrun or output error: %d\n"
		, cnt);
		exit(EXIT_FAILURE);
	}

	err = system(tc_cmdbuf);
	err_status = WEXITSTATUS(err);
	if (!WIFEXITED(err) || err_status != 0) {
		printf("Unable to replace/add qdisc clsact, command: "
		"%s  Error: (%d) %s\n", tc_cmdbuf, err, strerror(err));
		exit(EXIT_FAILURE);
	}

	// Use consistent "tc" handle and pref to overwrite any pre-existing.
	// Chain should also be consistent, but chain zero is implicit/default.
	// (Note: tc "replace" is same as "add" if not already present.)
	cnt = snprintf(tc_cmdbuf, sizeof(tc_cmdbuf)
	, "tc filter replace dev %s egress "
	"pref %d handle %d bpf da obj %s sec classifier verbose"
	, ifname, XDP_BYPASS_IPVS_TC_PREF, XDP_BYPASS_IPVS_TC_HANDLE
	, bpf_filename);
	if (cnt < 0 || cnt >= sizeof(tc_cmdbuf)) {
		printf("Unable to set up 'tc' command to load egress "
		"hook, command length overrun or output error: %d\n", cnt);
		exit(EXIT_FAILURE);
	}

	err = system(tc_cmdbuf);
	err_status = WEXITSTATUS(err);
	if (!WIFEXITED(err) || err_status != 0) {
		printf("Unable to replace/add egress BPF hook, command:\n"
		"    %s\n  Error: (%d) %s\n", tc_cmdbuf, err, strerror(err));
		exit(EXIT_FAILURE);
	}
}

// replace_tc_bpf_all
//
// Invokes replace_tc_bpf() for all interfaces, Internet and Server sides.
// Since an error is non-recoverable, causing replace_tc_bpf to exit, all
// "tc" modules will be installed upon completion.
static void
replace_tc_bpf_all (char * bpf_filename)
{
	int	idx;
	interface_info_t * intfp;

	// Only do this once per invocation.
	if (tc_loaded)
		return;

	for (idx = 1 ; idx < TC_MAX_LINKS; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex)
			continue;
		replace_tc_bpf(bpf_filename, intfp->ifname);
	}

	tc_loaded = 1;
}

// Associate inbound/outbound interface XDP programs with NIC, skb, or program
// array associated with a NIC.
static void
replace_xdp_bpf (char * bpf_filename, struct bpf_object * kern_bpf_objs
, struct bpf_program * inbound_prog_obj, struct bpf_program * dummy_prog_obj
, interface_info_t * intfp)
{
	int	dummy_prog_fd;
	int	err;
	void	* ecbpf_ctx;
	int	inbound_prog_fd;

	// Do NIC/SKB mode or program array insertion.
	if (!xdp_bypass_params_curr.mode_progarray) {
		// Required maps and XDP programs present and located,
		// load into kernel.
		if (bpf_object__load(kern_bpf_objs)) {
			printf("Unable to load '%s' objects into kernel \n"
			, bpf_filename);
			exit(EXIT_FAILURE);
		}

		// Set up file descriptors for those now-loaded XDP programs so
		// that they can be associated with NIC or SKB point.   Note
		// that need the XDP inbound program or just a dummy program
		// depending upon whether interface is Internet-facing or
		// solely outbound/server-facing (should BPF REDIRECT be used).
		if (intfp->tc_info.if_flags & TC_INTF_F_INTERNET) {
			inbound_prog_fd = bpf_program__fd(inbound_prog_obj);
			if (inbound_prog_fd < 0) {
				printf("Unable to get file descriptor for "
				"inbound XDP '%s'\n"
				, XBI_QUOTE_SYM(XBI_INBOUND_PROG_NAME));
				exit(EXIT_FAILURE);
			}

			// XXX: This should be using libecbpf
			if (bpf_xdp_attach(intfp->ifindex, inbound_prog_fd
			, xdp_flags, NULL) < 0) {
				printf("ERROR: link set xdp fd failed on input "
				"interface %s ifindex: %d\n"
				, intfp->ifname, intfp->ifindex);
				exit(EXIT_FAILURE);
			}
		} else if (intfp->tc_info.if_flags & TC_INTF_F_INSIDE) {
			dummy_prog_fd = bpf_program__fd(dummy_prog_obj);
			if (dummy_prog_fd < 0) {
				printf("Unable to get file descriptor for "
				"dummy XDP '%s'\n"
				, XBI_QUOTE_SYM(XBI_DUMMY_PROG_NAME));
				exit(EXIT_FAILURE);
			}
			// XXX: This should be using libecbpf
			if (bpf_xdp_attach(intfp->ifindex, dummy_prog_fd
			, xdp_flags, NULL) < 0) {
				printf("ERROR: link set xdp fd failed on "
				"output interface: %s ifindex: %d\n"
				, intfp->ifname, intfp->ifindex);
				exit(EXIT_FAILURE);
			}
		}
	} else if (intfp->tc_info.if_flags & TC_INTF_F_INTERNET) {
		// Program array mode, setup for it to do load & program array
		// This is only done for inbound/Internet-facing interfaces.
		ecbpf_ctx = ecbpf_ctx__new();
		if (!ecbpf_ctx) {
			printf("Unable to allocate libecbpf ctx to load.\n");
			exit(EXIT_FAILURE);
		}

		// Set context for already-parsed objects, interface, XDP mode.
		err = ecbpf_ctx__set_bpf_obj(ecbpf_ctx, kern_bpf_objs);
		if (err) {
			printf("Unexpected error setting BPF objects in ecbpf "
			"state:\n  error: (%d) %s\n"
			, err, strerror(err));
			exit(EXIT_FAILURE);
		}

		if (ecbpf_ctx__set_interface(ecbpf_ctx, intfp->ifname)) {
			printf("Unexpected failure setting interface %s in "
			"ecbpf state.\n", intfp->ifname);
			exit(EXIT_FAILURE);
		}

		ecbpf_ctx__set_subprogram_update(ecbpf_ctx, true);

		err = ecbpf__subprogram_attach(ecbpf_ctx, "xdp_bypass_ipvs"
		, xdp_prog_array_idx);
		if (err) {
			printf("Unable to set XDP in program array, err: %d.\n"
			, err);
			exit(EXIT_FAILURE);
		}

		ecbpf_ctx__free(ecbpf_ctx);
	}
}

// replace_xdp_bpf_all
//
// Invoke replace_xdp_bpf() for each interface, whether inbound/Internet or
// not.   The non-Internet interfaces may require a "dummy" XDP program to
// permit the redirect option.  Note that the BPF objects have to be set up
// for each interface/invocation.
//
// TODO: Consider and remove the above-mentioned redirect functionality from
// user and kernel code.
static void
replace_xdp_bpf_all (char * bpf_xdp_fname)
{
	int	dummy_prog_fd;
	struct bpf_program * dummy_prog_obj;
	int	err;
	struct bpf_object_open_opts file_open_opts;
	int	ifx;
	struct bpf_program * inbound_prog_obj;
	interface_info_t * intfp;
	struct bpf_object * kern_bpf_objs;
	int	mapx;
	libbpf_print_fn_t prior_print_fn;

	for (ifx = 1 ; ifx < TC_MAX_LINKS ; ifx++) {
		intfp = &interface_info[ifx];
		if (!intfp->ifindex
		|| !(intfp->tc_info.if_flags & TC_INTF_F_INTERNET))
			continue;

		// Locate all program and map objects from XDP kernel .o file.
		memset(&file_open_opts, 0, sizeof(file_open_opts));
		file_open_opts.sz = sizeof(file_open_opts);
		file_open_opts.object_name = NULL;
		file_open_opts.relaxed_maps = true;

		// Turn off printing from the relaxed_maps setting that
		// causes warnings, just for open call.
		//
		// TOCONSIDER: This not reusing objectcode?
		prior_print_fn = NULL;
		prior_print_fn = libbpf_set_print(prior_print_fn);
		kern_bpf_objs = bpf_object__open_file(bpf_xdp_fname
		, &file_open_opts);
		prior_print_fn = libbpf_set_print(prior_print_fn);

		err = libbpf_get_error(kern_bpf_objs);
		if (err) {
			// Error case, repeat open with libbpf printing for
			// all the  details.
			file_open_opts.sz = sizeof(file_open_opts);
			file_open_opts.object_name = NULL;
			file_open_opts.relaxed_maps = true;
			(void)bpf_object__open_file(bpf_xdp_fname
			, &file_open_opts);
			printf("\nbpf_object__open_file of %s error:\n  "
			"(%d) %s\n"
			, bpf_xdp_fname, err, strerror(err));
			exit(EXIT_FAILURE);
		}

		// Find map objects within the kernel objects and point them to
		// the file descriptors of the actual pinned maps that are
		// shared across all eBPF programs.
		for (mapx = 0 ; mapx < sizeof(mapinfo)/sizeof(mapinfo[0])
		; mapx++) {
			struct bpf_map * map_obj;

			map_obj = bpf_object__find_map_by_name(kern_bpf_objs
			, mapinfo[mapx].mi_name);
			if (!map_obj) {
				printf("Pinned map %s exists in BPF FS, but not"
				" in XDP kern .o file.   Force full unload?\n"
				, mapinfo[mapx].mi_name);
				exit(EXIT_FAILURE);
			}

			err = bpf_map__reuse_fd(map_obj, mapinfo[mapx].mi_fd);
			if (err) {
				printf("Failure pointing map object to pinned "
				"map %s, error: (%d) %s\n"
				, mapinfo[mapx].mi_name, err, strerror(err));
				exit(EXIT_FAILURE);
			}
		}

		// Locate our inbound XDP and dummy XDP program objects as
		// present in the .o file opened.  Set their program types so
		// they will at least load into the kernel.
		inbound_prog_obj
		= bpf_object__find_program_by_name(kern_bpf_objs
		, XBI_QUOTE_SYM(XBI_INBOUND_PROG_NAME));
		if (!inbound_prog_obj) {
			printf("Unable to find inbound XDP program '%s' in "
			"kern .o\n"
			, XBI_QUOTE_SYM(XBI_INBOUND_PROG_NAME));
			exit(EXIT_FAILURE);
		}

		dummy_prog_obj = bpf_object__find_program_by_name(kern_bpf_objs
		, XBI_QUOTE_SYM(XBI_DUMMY_PROG_NAME));
		if (!dummy_prog_obj) {
			printf("Unable to find dummy XDP program '%s' in "
			"kern .o\n"
			, XBI_QUOTE_SYM(XBI_DUMMY_PROG_NAME));
			exit(EXIT_FAILURE);
		}

		// Set both XDP program types that will be loaded.
		bpf_program__set_type(inbound_prog_obj, BPF_PROG_TYPE_XDP);
		bpf_program__set_type(dummy_prog_obj, BPF_PROG_TYPE_XDP);

		// Now insert the XDP program for this interface.
		// ecbpf_ctx__free() there-in also frees up the kernel BPF
		// objects array.   This is fine since libbpf does not allow
		// reuse of the same object anyway even though there should be
		// minimal change between subsequent usage.  Just rebuild it
		// for each NIC, possibly incurring additional program memory
		// costs(?), since this is just one-time initialization.
		replace_xdp_bpf(bpf_xdp_fname, kern_bpf_objs
		, inbound_prog_obj, dummy_prog_obj, intfp);
	}

	xdp_loaded = 1;
}

// Remove tc and xdp eBPF programs from NIC or SKB, then unpin all the maps
// Note that removing xdp from NIC point would normally lead to ring
// juggling/delays but we leave the "dummy" program, if any, on the output
// interface and insert/overwrite the nop_kern.o in the current directory
// into the input interface.
//
// Note that error conditions do not prevent proceeding in an attempt to
// clean up anything that can be, since requested by user.
//
static void
unload_tc_xdp_unpin (char ** argv, int force_flag)
{
	int	cnt;
	void	* ecbpf_ctx;
	int	err;
	int	err_status;
	int	idx;
	interface_info_t * intfp;
	char	map_path[PATH_MAX];
	char	tc_cmdbuf[MAX_FILENAME + 100];
	int	tc_running;
	int	xdp_running;

	// Require -F (force) option if all appears to be running
	tc_running = check_tc_running_all(argv[0]);
	xdp_running = check_xdp_running_all();
	if (tc_running && xdp_running && !force_flag) {
		printf("tc and xdp running, unload requires -F "
		"to force termination and do map unpins\n");
		exit(EXIT_FAILURE);
	}

	// XDP removal for SKB just requires nulling the association
	// This has no driver/NIC reinitialization implication, so no need to
	// replace with NOP program.
	if (xdp_flags & XDP_FLAGS_SKB_MODE) {
		for (idx  = 1 ; idx < TC_MAX_LINKS ; idx++) {
			if (!interface_info[idx].ifindex)
				continue;
			// XXX: This should be using libecbpf
			bpf_xdp_detach(interface_info[idx].ifindex
			, xdp_flags, NULL);
		}
		xdp_loaded = 0;
	} else if (!xdp_bypass_params_curr.mode_progarray) {
		// For NIC XDP, Replace XDP point(s) with current nop_kern.o
		// This prevents driver/NIC reinitialization.
		//
		// TOCONSIDER: Loads nop.o multiple times, reuse single object?
		// But this mode is primarily a test/development one, not
		// production.
		load_current_nop_xdp_all();
	} else {
		// Program array mode, detach from all inbound/Internet
		// interfaces.
		detach_xdp_prog_all();
	}

	// Set up tc delete command for each interface, this will delete all
	// output egress from both Internet and Server side interfaces..
	//
	// TODO: We should only delete single eBPF inserted on output device.
	// This form would delete other egress eBPF, should such ever exist.
	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++) {
		intfp = &interface_info[idx];
		if (!intfp->ifindex)
			continue;
		cnt = snprintf(tc_cmdbuf, sizeof(tc_cmdbuf)
		, "tc filter delete dev %s egress ", intfp->ifname);
		if (cnt < 0 || cnt >= sizeof(tc_cmdbuf)) {
			// Exiting here since something programmatically wrong.
			printf("Unable to set up 'tc' command to delete egress "
			"hook, command length overrun or output error: %d\n"
			, cnt);
			exit(EXIT_FAILURE);
		}

		err = system(tc_cmdbuf);
		err_status = WEXITSTATUS(err);
		if (!WIFEXITED(err) || err_status != 0) {
			printf("Unable to delete egress BPF hook, command: "
			"%s  Error: (%d) %s\n", tc_cmdbuf, err, strerror(err));
		}
	}

	// Loop to unlink/unpin all maps, continue despite any errors so that
	// all can be cleaned up.  The underlying maps should be freed since
	// components above have been replaced/removed.
	for (idx = 0 ; idx < sizeof(mapinfo)/sizeof(mapinfo[0]) ; idx++) {
		// Confirm pinned map exists by opening and getting file handle
		cnt = snprintf(map_path, sizeof(map_path), "%s/%s"
		, TC_GLOBAL_MAPS_PATH, mapinfo[idx].mi_name);
		if (cnt < 0 || cnt >= sizeof(map_path)) {
			// Have to skip this one, but may as well try others.
			printf("map_path %s/%s too length overrun or output "
			" error: %d\n"
			, TC_GLOBAL_MAPS_PATH, mapinfo[idx].mi_name, cnt);
			continue;
		}

		err = unlink(map_path);
		if (err) {
			printf("Unable to unlink map: %s\n    error: (%d) %s\n"
			"Proceeding with remaining operations.\n\n"
			, map_path, errno, strerror(errno));
		}
	}
}

// Update parameters map with the latest settings specified here, do not
// store built-in defaults which other commands may have overridden
//
// Also update the ip and hardware address maps.
static void
update_params_addrs_maps (void)
{
	__be32	* addr_keyp;
	int	af_family;
	int	idx;
	__u32	ifservice;
	int	in_pps_recalc = 0;
	interface_info_t * intfp;
	int	map_fd;
	int	out_pps_recalc = 0;
	int	ret;
	int	updated = 0;
	int	v4addrs_cnt;
	int	v6addrs_cnt;
	__be32	v4addr_key;
	__be32	* v4addr_keyp;
	__be32	v4addr_nextkey;
	struct in6_addr	v6addr_key;
	struct in6_addr	* v6addr_keyp;
	struct in6_addr	v6addr_nextkey;

	// Current parameters map already read, update any changes made
	// in this program's invocation that should update the current params.
	// TODO: See earlier comment about uniform sizes, to make this simpler.
	if (inactive_nsecs_flag) {
		xdp_bypass_params_curr.inactive_nsecs
		= xdp_bypass_params.inactive_nsecs;
		updated = 1;
	}
	if (sample_nsecs_flag) {
		xdp_bypass_params_curr.sample_nsecs
		= xdp_bypass_params.sample_nsecs;
		updated = 1;
	}
	if (monitor_only_flag) {
		xdp_bypass_params_curr.monitor_only
		= xdp_bypass_params.monitor_only;
		updated = 1;
	}
	if (use_xdp_tx_flag) {
		xdp_bypass_params_curr.use_xdp_tx
		= xdp_bypass_params.use_xdp_tx;
		updated = 1;
	}
	if (vlan_hdr_tag_flag) {
		xdp_bypass_params_curr.vlan_hdr_tag
		= xdp_bypass_params.vlan_hdr_tag;
		updated = 1;
	}
	if (mode_progarray_flag) {
		xdp_bypass_params_curr.mode_progarray
		= xdp_bypass_params.mode_progarray;
		updated = 1;
	}
	if (limit_rates_flag) {
		xdp_bypass_params_curr.limit_rates
		= xdp_bypass_params.limit_rates;
		updated = 1;
	}
	if (in_wrap_cnt_flag) {
		xdp_bypass_params_curr.in_wrap_cnt
		= xdp_bypass_params.in_wrap_cnt;
		in_pps_recalc = 1;
                updated = 1;
	}
	if (rx_rps_cpus_flag) {
		xdp_bypass_params_curr.rx_cpus = xdp_bypass_params.rx_cpus;
		xdp_bypass_params_curr.rps_cpus = xdp_bypass_params.rps_cpus;
		in_pps_recalc = 1;
		out_pps_recalc = 1;
                updated = 1;
	}
	if (inbound_pps_flag) {
		xdp_bypass_params_curr.inbound_pps
		= xdp_bypass_params.inbound_pps;
		in_pps_recalc = 1;
                updated = 1;
	}
	if (inbound_spike_flag) {
		xdp_bypass_params_curr.inbound_spike
		= xdp_bypass_params.inbound_spike;
		in_pps_recalc = 1;
                updated = 1;
	}
	if (inbound_max_flag) {
		xdp_bypass_params_curr.inbound_max
		= xdp_bypass_params.inbound_max;
		in_pps_recalc = 1;
                updated = 1;
	}
	if (max_reset_pps_flag) {
		xdp_bypass_params_curr.max_reset_pps
		= xdp_bypass_params.max_reset_pps;
		out_pps_recalc = 1;
                updated = 1;
	}

	if (updated || !xdp_bypass_params_curr_pinned) {
		int err;

		// Some parameters require recalculations before map update
		// if either parameters changed or input probability table
		// never initialized.
		if (out_pps_recalc)
			update_params_out_pps();
		if (in_pps_recalc || !xdp_bypass_params_curr.prob_256[0])
			update_params_in_pps();

		// Update (existing?) pinned map with latest current settings
		idx = 0;
		err = bpf_map_update_elem(mapinfo[MAP_IDX_PARAMS].mi_fd
		, &idx, &xdp_bypass_params_curr
		, xdp_bypass_params_curr_pinned ? BPF_EXIST : BPF_ANY);
		// Should not fail, hopefully there is a useful errno.
		if (err) {
			printf("Something wrong with parameters map update, "
			"error: (%d) %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	// Always assure local addresses are current in their maps.
	//
	// Gather all IP[v6] addresses from all specified inbound and out
	// interfaces, as well as the optional additional addresses interfaces
	// from the -a option.  These are necessary for both XDP inbound and
	// TC outbound processing so as to avoid fastpath processing for local
	// addresses.
	//
	// Before inserting into the actual map, zap all pre-existing entries
	// to inactive in case there were interface address changes.

	// Gather all IP[v6] addresses into their respective arrays.
	v4addrs_cnt = 0;
	v6addrs_cnt = 0;
	for (intfp = &interface_info[0]
	; intfp != &interface_info[TC_MAX_LINKS] ; intfp++) {
		if (!intfp->ifindex)
			continue;

		if (v4addrs_cnt < XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS) {
			ret = v4_get_ifaddrs(intfp->ifindex
			, &v4_addrs[v4addrs_cnt]
			, XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS - v4addrs_cnt);
			if (ret < 0) {
				printf("*** Abort getting v4 addrs. ***\n");
				exit(EXIT_FAILURE);
			}
			v4addrs_cnt += ret;
		} else {
			printf("\n*** Limit of %d local IPv4 addresses reached "
			"while on interface %s.  Invalid to proceed. ****\n"
			, XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS, intfp->ifname);
			exit(EXIT_FAILURE);
		}

		if (v6addrs_cnt < XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS) {
			ret = v6_get_ifaddrs(intfp->ifindex
			, &v6_addrs[v6addrs_cnt]
			, XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS - v6addrs_cnt);
			if (ret < 0) {
				printf("*** Abort getting v6 addrs. ***\n");
				exit(EXIT_FAILURE);
			}
			v6addrs_cnt += ret;
		} else {
			printf("\n*** Limit of %d local IPv6 addresses reached "
			"while on interface %s.  Invalid to proceed. ****\n"
			, XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS, intfp->ifname);
			exit(EXIT_FAILURE);
		}
	}

	// Update IPv4 local addrs map.  Error if we did not find/get any.
	if (v4addrs_cnt + v6addrs_cnt == 0) {
		printf("*** No local addrs found, invalid to proceed. ***\n");
		exit(EXIT_FAILURE);
	}

	// IPv4 address updating.

	// First add addresses from our list of current addresses to the hash.
	// Set the "in interface service" flag to distinguish addresses on
	// configured interfaces from non-configured interface addresses.
	ifservice = 1;
	for (idx = 0 ; idx < v4addrs_cnt ; idx++) {
		if (bpf_map_update_elem(mapinfo[MAP_IDX_V4LADDRS].mi_fd
		, &v4_addrs[idx], &ifservice, BPF_ANY)) {
			printf("*** Unable to insert local IPv4 in map! ***\n");
			exit(EXIT_FAILURE);
		}
	}

	// Now walk through the map again, cleaning up any entries not found
	// in our current list of local addresses AND are marked as an interface
	// address.
	v4addr_keyp = NULL;
	bool address_found = false;
	for (;;) {
		if (bpf_map_get_next_key(mapinfo[MAP_IDX_V4LADDRS].mi_fd
		, v4addr_keyp, &v4addr_nextkey)) {
			// At end of entries, done marking for future delete.
			break;
		}

		v4addr_key = v4addr_nextkey;

		// Check that the address is current
		address_found = false;
		for (idx = 0 ; idx < v4addrs_cnt ; idx++) {
			if (v4_addrs[idx] == v4addr_key) {
				address_found = true;
				break;
			}
		}

		// If map address is not currently on a configured interface
		// check its record to make sure it used to be, then delete it.
		if (!address_found
		&& bpf_map_lookup_elem(mapinfo[MAP_IDX_V4LADDRS].mi_fd
		, &v4addr_keyp, &ifservice) == 0
		&& ifservice) {
			// No longer in service on an interface, delete.
			// And restart hash over due to mutating it.
			(void)bpf_map_delete_elem
			(mapinfo[MAP_IDX_V4LADDRS].mi_fd, &v4addr_key);
			v4addr_keyp = NULL;
		} else {
			// Map address still configured OR is not a configured
			// interface address, move on in both cases.
			v4addr_keyp = &v4addr_key;
		}
	}

	// IPv6 address updating.

	// First add addresses from our list of current addresses to the hash.
	// Set the "in interface service" flag to distinguish addresses on
	// configured interfaces from non-configured interface addresses.
	ifservice = 1;
	for (idx = 0 ; idx < v6addrs_cnt ; idx++) {
		if (bpf_map_update_elem(mapinfo[MAP_IDX_V6LADDRS].mi_fd
		, &v6_addrs[idx], &ifservice, BPF_ANY)) {
			printf("*** Unable to insert local IPv6 in map! ***\n");
			exit(EXIT_FAILURE);
		}
	}

	// Now walk through the map again, cleaning up any entries not found
	// in our current list of local addresses.
	v6addr_keyp = NULL;
	for (;;) {
		if (bpf_map_get_next_key(mapinfo[MAP_IDX_V6LADDRS].mi_fd
		, v6addr_keyp, &v6addr_nextkey)) {
			// At end of entries, done marking for future delete.
			break;
		}

		v6addr_key = v6addr_nextkey;

		// Check that the address is current
		address_found = false;
		for (idx = 0 ; idx < v6addrs_cnt ; idx++) {
			if (memcmp(&v6_addrs[idx], &v6addr_key, sizeof(struct in6_addr)) == 0) {
				address_found = true;
				break;
			}
		}

		// If map address is not currently on a configured interface
		// check its record to make sure it used to be, then delete it.
		if (!address_found
		&& bpf_map_lookup_elem(mapinfo[MAP_IDX_V6LADDRS].mi_fd
		, &v6addr_keyp, &ifservice) == 0
		&& ifservice) {
			// No longer in service on an interface, delete.
			// And restart hash over due to mutating it.
			(void)bpf_map_delete_elem
			(mapinfo[MAP_IDX_V6LADDRS].mi_fd, &v6addr_key);
			v6addr_keyp = NULL;
		} else {
			// Map address still configured OR is not a configured
			// interface address, move on in both cases.
			v6addr_keyp = &v6addr_key;
		}
	}

	// Add or Delete any excluded addresses specified on the command line.
	// These addresses should NOT appear in the interfaces-derived list
	// above, if they do then an abort is done to bring attention to this
	// configuration error.
	for (idx = 0 ; idx < ex_addrscnt ; idx++) {
		char	* errtextp;
		char	* errtext2p;

		af_family = ex_addrsp[idx].ai_family;
		if (af_family == AF_INET) {
			addr_keyp = (__be32 *)&ex_addrsp[idx].ai_in4;
			map_fd = mapinfo[MAP_IDX_V4LADDRS].mi_fd;
		} else {
			addr_keyp = (__be32 *)&ex_addrsp[idx].ai_in6;
			map_fd = mapinfo[MAP_IDX_V6LADDRS].mi_fd;
		}

		errtextp = NULL;
		ret = bpf_map_lookup_elem(map_fd, addr_keyp, &ifservice);
		if (ex_mode == 1) {
			if (ret) {
				// Add non-configured address since no conflict.
				ifservice = 0;
				if (bpf_map_update_elem(map_fd, addr_keyp
				, &ifservice, BPF_ANY)) {
					errtextp = "Error inserting new";
					errtext2p = "(error unknown)";
				}
			} else if (ifservice) {
				// Address in table conflicts, is for interface.
				errtextp = "Conflict inserting";
				errtext2p = "Address on configured interface";
			}
		} else if (ex_mode == 2) {
			// Delete of a non-existent record, race or cleanup?
			// Just confirm any existing one is not for a configured
			// interface.
			if (!ret && ifservice) {
				errtextp = "Conflict deleting";
				errtext2p = "Address on configured interface";
			}

			// Delete address if present, do not care if not.
			(void)bpf_map_delete_elem(map_fd, addr_keyp);
			ret = 0;
		}

		if (errtextp) {
			// If error texts set then some abort condition arose.
			char	tmpaddr[INET6_ADDRSTRLEN];

			printf("*** %s excluded %s %s address.\n"
			"*** %s.\n"
			, errtextp
			, af_family == AF_INET ? "AF_INET" : "AF_INET6"
			, inet_ntop(af_family, addr_keyp, tmpaddr
			, sizeof(tmpaddr))
			, errtext2p);
			exit(EXIT_FAILURE);
		}
	}

	// For commands other than (un)load, no need to update the interface
	// map since it had been read in during initialization, unless the -a
	// modified the address interfaces.
	if (!load_flag && !unload_flag && !ifaddrscnt)
		return;

	// Set up interfaces map with hardware addresses and other info.
	// Walk through map as well as local array, unmarking any map entries
	// that are no longer current.
	for (idx = 1 ; idx < TC_MAX_LINKS ; idx++ ) {
		if (!interface_info[idx].ifindex) {
			if (bpf_map_lookup_elem(mapinfo[MAP_IDX_INTERFACES]
			.mi_fd, &idx, &interface_info[idx].tc_info) < 0)
				continue;
			if (!interface_info[idx].tc_info.if_flags)
				continue;
			interface_info[idx].tc_info.if_flags = 0;
		}

		if (bpf_map_update_elem(mapinfo[MAP_IDX_INTERFACES].mi_fd, &idx
		, &interface_info[idx].tc_info, BPF_ANY)) {
			printf("*** Unable to update/insert interface for "
			"interface: %s  ifindex: %d\n"
			, interface_info[idx].ifname
			, interface_info[idx].ifindex);
			exit(EXIT_FAILURE);
		}
	}
}

// update_params_in_pps
//
// Update the calculated fields within the parameters map element, based on
// the options/configuration specified.  Elapsed times for packet arrival
// rates are calculated as well as a probability table along with a divisor
// to index into it at various rates.  At this time, also reset the inbound CPU
// rate maps so they get calculated consistent with the latest settngs.

/***********************************************************************

Background along with details/examples for this method

The whole purpose of this seemingly complex code for a rate calculation
is to avoid as much math as possible in the hot kernel XDP eBPF paths.
The below, through use of a pre-calculated probability table and a
run-time calculated divisor, limits the eBPF code to doing a single
inbound division once per sample period and then just simple table
lookups/compares for the other 99.98% of packets (4095 of the 4096
default sample size).

Example of 10G, single-NIC, bond0 piping out to a traditional bond1
could be configured as follows with a target rate of 8Mpps for the box
and 8 RX CPUs that divide up that rate evenly:

Target rate from command line: 8,000,000+5+75 (Don't drop thru 5% spike,
max at %75 rate of 14Mpps).  In reality, choosing a divisor for the table
below may not drop packets "soon enough" and on our hardware we can not
get 14Mpps line rate into memory, let alone processed.   So choosing
a lower "max" will increase the probability of a packet being dropped
when we are over the target bandwidth.

8Mpps -> 1Mpps per-cpu
+5%   -> 1.05Mpps per-cpu
+75%  -> 1.75Mpps per-cpu

At wrap/sample count of 4096 packets that calculates to timings of:

1Mpps - 1000000000ns/sec * 4096 pkts / 1000000pps -> 4096000ns
1.05Mpps - 1000000000ns/sec * 4096 pkts / 1050000pps -> 3900952ns
1.75Mpps - 1000000000ns/sec * 4096 pkts / 1750000pps -> 2338816ns

Divisor is chosen by using the number of buckets below for the difference
between the targeted 1Mpps sample time of just over 4ms and the 2.3ms
of the configured maximum rate:

Divisor = (4096000ns - 2338816ns) / 16 = 109824ns

The above puts that "max" value, 14Mpps (1.75Mpps per-CPU), at the highest
drop probability in the table.  Lowering that "max" will thus increase the
probability of dropping packets as mentioned above.

Prototype shell script to visualize the probability table built by
default (this was a single line originally, be wary of line wraps):

PERCENT=100 ; INDEX=0 ; while [ true ] ; do echo Index: $INDEX  Keep if random\&0xff \<= value: $(( ($PERCENT * 256) / 100 )) Percent: $PERCENT ; INDEX=$(( $INDEX + 1 )) ; if [ $INDEX -gt 15 ] ; then break ; fi ; if [ $PERCENT -ge 7 ] ; then PERCENT=$(( $PERCENT - 7 )) ; else PERCENT=0 ; fi ; done
Index: 0 Keep if random&0xff <= value: 256 Percent: 100
Index: 1 Keep if random&0xff <= value: 238 Percent: 93
Index: 2 Keep if random&0xff <= value: 220 Percent: 86
Index: 3 Keep if random&0xff <= value: 202 Percent: 79
Index: 4 Keep if random&0xff <= value: 184 Percent: 72
Index: 5 Keep if random&0xff <= value: 166 Percent: 65
Index: 6 Keep if random&0xff <= value: 148 Percent: 58
Index: 7 Keep if random&0xff <= value: 130 Percent: 51
Index: 8 Keep if random&0xff <= value: 112 Percent: 44
Index: 9 Keep if random&0xff <= value: 94 Percent: 37
Index: 10 Keep if random&0xff <= value: 76 Percent: 30
Index: 11 Keep if random&0xff <= value: 58 Percent: 23
Index: 12 Keep if random&0xff <= value: 40 Percent: 16
Index: 13 Keep if random&0xff <= value: 23 Percent: 9
Index: 14 Keep if random&0xff <= value: 5 Percent: 2
Index: 15 Keep if random&0xff <= value: 0 Percent: 0

On the above, note that rates below 8Mpps simply do not consult this
table.  They are eliminated by a simple comparison of the sample time
with the calculated 8Mpps 4096000ns.   Its only above the 8Mpps + spike
percent that the table is consulted and a probability drop done.

Also note that the 5% spike, up to 1.05Mpps, is "protected" from the
index 1 bucket due to an explicit range check in the code.   So there
will be no drops at that level.  But the next 2% beyond that 1.05Mpps
will still be subjected to that 93% "keep" probability.  For example,
even at 1.055Mpps the 93% keep probability is hit:

1.055Mpps - 1000000000ns/sec * 4096 / 1055000pps -> 3882464ns

Index/bucket calculation: (4096000ns - 3882464ns) / 109824ns = 1

Choosing a lower Max, such as 30-50%, will result in more packets being
dropped after exceeding the spike limit and leave CPU for processing
the known flow packets.  But at the cost/risk of hurting newer legitimate
flows at busy/peak times or attacks.

***********************************************************************/

static void
update_params_in_pps (void)
{
	struct timespec currtime;
	uint	idx;
	xdp_inbound_rates_t * in_ratep;
	xdp_inbound_rates_t * in_rate_allp;
	uint	num_cpus;
	xdp_bypass_params_t * paramsp;
	uint	percpu_rate;
	__u64	percpu_wrap;
	uint	percent_curr;
	uint	percent_intvl;

	paramsp = &xdp_bypass_params_curr;
	num_cpus = libbpf_num_possible_cpus();

	// Allocate the full inbound per-CPU map buffer.
	in_rate_allp = (xdp_inbound_rates_t *)malloc(num_cpus
	* sizeof(xdp_inbound_rates_t));
	if (!in_rate_allp) {
		printf("\n*** Unable to allocate %u CPUS of %lu byte per-CPU "
		"entries to update inbound rates. ***\n\n"
		, num_cpus, sizeof(xdp_inbound_rates_t));
		exit(EXIT_FAILURE);
	}

	// Calculate per-CPU inbound packet sample/wrap time ns based on the
	// number of CPUs and specified rates.   Also apply the spike
	// percentage and figure out the minimum time ns.
	percpu_rate = paramsp->inbound_pps / paramsp->rx_cpus;
	paramsp->wrap_target_ns = (NSECS_PER_SEC * (__u64)paramsp->in_wrap_cnt)
	/ (__u64)percpu_rate;

	percpu_rate = ((paramsp->inbound_pps * (100 + paramsp->inbound_spike))
	/100) / paramsp->rx_cpus;
	paramsp->wrap_min_ns = (NSECS_PER_SEC * (__u64)paramsp->in_wrap_cnt)
	/ (__u64)percpu_rate;

	// Calculate probability byte array, in order of increasing probability
	// to drop the packet, so zeroth element has an impossible byte value to
	// exceed of 256.
	// This is a linear array based on the default percentage interval for
	// the # of buckets, with a round-up so any negative probability(!) is
	// simply set to the "almost certain to drop" value of zero.
	percent_intvl = (100 + XBI_PARAMS_PROB_256 - 1)
	/ XBI_PARAMS_PROB_256;

	percent_curr = 100;
	for (idx = 0 ; idx < XBI_PARAMS_PROB_256 ; idx++) {
		paramsp->prob_256[idx] = percent_curr * 256 / 100;
		if (percent_intvl <= percent_curr)
			percent_curr -= percent_intvl;
		else
			percent_curr = 0;
	}

	// The divisor to index into the above probability array is calculated
	// so the last bucket is for the specified "min" wrap rate configured.
	// Anything faster than that rate will select the last bucket, so the
	// probability is only linear in the specified range.  This can allow
	// an artificially low "cap" to increase the packet drop rates beyond
	// the targeted value.
	paramsp->prob_divisor = (__u32)((paramsp->wrap_target_ns
	- paramsp->wrap_min_ns ) /XBI_PARAMS_PROB_256);

	// Now initialize the values in the inbound per-CPU rate map that will
	// cause subsequent packets to use the new parameters about to be
	// installed.
	// All configured entries are initialized, even if far less than the
	// actual number of CPUs.
	memset((void *)in_rate_allp, 0, num_cpus * sizeof(*in_ratep));
	(void)clock_gettime(CLOCK_MONOTONIC, &currtime);
	for (idx = 0 ; idx < num_cpus ; idx++ ) {
		in_ratep = &in_rate_allp[idx];

		// Set time to be several "wraps" in the past, so very unlikely
		// to get a burst of spurious rate limiting.  Do per entry
		// so doesn't "drift" much if scheduled out/interrupted.
		in_ratep->ltime_wrap_ns = currtime.tv_sec * NSECS_PER_SEC
		+ currtime.tv_nsec - 8 * paramsp->wrap_target_ns;
	}

	// Above sets up the 0th (single entry) per-CPU, now update all at once.
	idx = 0;
	if (bpf_map_update_elem(mapinfo[MAP_IDX_IN_RATES].mi_fd, &idx
	, in_rate_allp, BPF_ANY)) {
		printf("\n*** Unable to update/insert inbound packet rate "
		"map entry for inbound per-CPU map. ***\n\n");
		exit(EXIT_FAILURE);
	}

	free(in_rate_allp);
}

// update_params_out_pps
//
// Update the calculated fields within the parameters map element, based on
// the options/configuration specified.  At this time, reset the outbound CPU
// rate maps so they get calculated consistent with the latest settngs.
static void
update_params_out_pps (void)
{
	struct timespec currtime;
	uint	idx;
	uint	num_cpus;
	tc_outbound_rates_t * out_ratep;
	tc_outbound_rates_t * out_rate_allp;
	xdp_bypass_params_t * paramsp;

	paramsp = &xdp_bypass_params_curr;
	num_cpus = libbpf_num_possible_cpus();

	// Allocate the full outbound per-CPU map buffer.
	out_rate_allp = (tc_outbound_rates_t *)malloc(num_cpus
	* sizeof(tc_outbound_rates_t));
	if (!out_rate_allp) {
		printf("\n*** Unable to allocate %u CPUS of %lu byte per-CPU "
		"entries to update outbound rates. ***\n\n"
		, num_cpus, sizeof(tc_outbound_rates_t));
		exit(EXIT_FAILURE);
	}

	// Calcuate the per-CPU outbound RST/reject rate based on the number
	// of CPUs and the configured pps rate.   Take the default epoch
	// fraction of a second of that as the "epoch" time, to smooth out the
	// rate-limiting of these packets.
	paramsp->out_rsts = (paramsp->max_reset_pps / paramsp->rps_cpus)
	/ MAX_RESETS_EPOCH_DEF;
	if (!paramsp->out_rsts && paramsp->max_reset_pps)
		paramsp->out_rsts = 1;
	paramsp->out_rsts_epoch_ns = NSECS_PER_SEC / MAX_RESETS_EPOCH_DEF;

	// Now initialize the values in the outbound per-CPU rate map that will
	// cause subsequent packets to use the new parameters about to be
	// installed.
	// Initialize all map entries, even if a subset of actual CPUs count.
	memset((void *)out_rate_allp, 0, num_cpus * sizeof(*out_ratep));
	(void)clock_gettime(CLOCK_MONOTONIC, &currtime);
	for (idx = 0 ; idx < num_cpus ; idx++ ) {
		out_ratep = &out_rate_allp[idx];

		// Set previous end time in the past so that it will start
		// the output limiting of RST/rejection packets.
		out_ratep->end_time_ns = currtime.tv_sec * NSECS_PER_SEC
		+ currtime.tv_nsec - NSECS_PER_SEC;
	}

	// Above initialized all 0th (only) entries for each CPU in outbound
	// map.   Now update them all in one shot.
	idx = 0;
	if (bpf_map_update_elem(mapinfo[MAP_IDX_OUT_RATES].mi_fd, &idx
	, out_rate_allp, BPF_ANY)) {
		printf("\n*** Unable to update/insert outbound CPU rate"
		" map entries for all CPUs. ***\n\n");
		exit(EXIT_FAILURE);
	}

	free(out_rate_allp);
}

// Display specified command and error string, along with usage/syntax help
static void
usage_and_exit (char * arg0, char * lasterror)
{
	if (lasterror)
		printf("\n***** %s *****\n\n", lasterror);

	printf("\nUsage:\n\n%s: [-F] [-M {off|on}] [-T] [-R {off|on}]\n"
	"  [-l {off|on}] [-p {off|on}]\n"
	"  [-v <vlan_hdr_tag>] [-r <inactive_seconds>]\n"
	"  [-s <sample_seconds>] [-S [<stats_seconds> [<stats_count>]] [-f]] "
	"[-P][-B]\n"
	"  [-c|--cpus-rx-rps <rx-cpus>[,<rps-cpus>]]\n"
	"  [-m|--max-resets-pps <packets-per-second>]\n"
	"  [-t|--inbound_pps <inbound-pps>[+<spike-percent>[+max-percent]]]\n"
	"  [-w|--wrap-packets-count <sample-count>]\n"
	"  [-a|--addrs-ifs <addrs-ifname>[,<addrs-ifname>]...]\n"
	"  [-e|--excluded-addrs {add|del[ete]} <v4|v6 address>"
	"[,<v4|v6 address>...]]\n"
	"  [{-L|-U} [-i|--inbound-ifs <ifname>[,<ifname>...]]\n"
	"  -o|--outbound-ifs <ifname>[,<ifname>...]]\n"
	"  [-z|--statsd-enable]\n"
	, arg0);

	printf("\nwhere:\n"
	"\n"
	"    -a, --addrs-ifs <addrs-ifname>[,<addrs-ifname>]\n"
	"\tAddresses from up to 2 existing interfaces to use to gather IP[v6]\n"
	"\taddresses that should not receive bypass processing.   These "
	"interfaces\n"
	"\tmay be the bond interfaces with the addresses, as opposed to the\n"
	"\tdriver interfaces used in the -i and -o options.  Examples:\n"
	"\t\t '... -i eth0 -o eth1 ... -a bond0,bond1'.\n"
	"\t\t '... -i eth0,eth1 -o bond0.10 ... -a bond0'.\n"
	"\t-F (force) may be used to avoid specifying this option in the case\n"
	"\twhere there are no addresses on the provided -i and -o options.\n"
	"\n"
	"    -B, --display-excluded-addrs\n"
	"\tDisplay addresses being excluded from the bypass processing "
	"picked up\n"
	"\tfrom the specified -a interface(s).  SRC address is checked on\n"
	"\tthe egress/outbound interface and packet DST address is checked"
	" on the\n"
	"\tXDP inbound interface.\n"
	"\n"
	"    -c, --cpus-rx-rps <rx-cpus>[,<rps-cpus>]\n"
	"\t<rx-cpus> is the total number of RX IRQ CPUs (to be) configured in "
	"the\n"
	"\tsystem, independent of the number of NICs sharing CPUs.  The "
	"default\n"
	"\tis %d CPUs but should only be used without checking if tuning is "
	"not\n"
	"\tcritical, such as in a functional test/development scenario.\n"
	"\tThe primary purpose of <rx-cpus> is to configure the expected rates "
	"of\n"
	"\tper-CPU RX handling by division of the --inbound-pps configs.\n"
	"\n"
	"\t<rps-cpus> is the total number of RPS CPUs, the packet-processsing "
	"CPUs\n"
	"\tscheduled by the RX IRQ CPUs.   The default value is calculated "
	"by\n"
	"\tsubtracting <rx-cpus> from the total number of available CPUs.\n"
	"\n"
	"    -e|--excluded-addrs {add|del[ete]} <v4|v6 address> [,<v4|v6 "
	"address>...]]\n"
	"\tAddition or deletion of addresses to skip bypass/fastpath "
	"processing.\n"
	"\tThese addresses are NOT already part of the configured -i, -o, "
	"or -a\n"
	"\tinterfaces.  There is no hard-limit on the number of addresses that "
	"may\n"
	"\tbe specified on either the command line or the result of multiple\n"
	"\tinvocations, other than BPF table size which is currently %d "
	"for the\n"
	"\tsum of all addresses from all the -i, -o, -a, and this -e option."
	"  v4\n"
	"\taddresses are dotted-decimal format and v6 addresses are in "
	"standard\n"
	"\tcolon-separated format.  Only unicast addresses are permitted,\n"
	"\tprefix/length specification is not supported.\n"
	"\n"
	"    -f, --flows-display-tcp\n"
	"\tTCP[v6]) sample flows should be displayed, one set with each "
	"stats set\n"
	"\tdisplayed.  Only valid with the -S/--statistics option below.\n"
	"\n"
	"    -F\n"
	"\tforce (re)Load or Unload as described for -L and -U options "
	"below as\n"
	"\twell as to skip the master address(es) interface(s) for the -i "
	"and -o\n"
	"\toptions below.  May be specified multiple times, such as for "
	"allowing\n"
	"\tkernel objects mismatch as well as force -L/-U operations.\n"
	"\n"
	"    -i, --inbound-ifs <ifname>[,<ifname>...]\n"
	"\tXDP bypass input interfaces, such as '-i eth0'.  Note that without\n"
	"\t-R packets are rewritten out the same interface with BPF XDP_TX\n"
	"\tinbound processing.  Packets are optionally VLAN-tagged.\n"
	"\t',<ifname>...' is a comma-separated list of interfaces for a total\n"
	"\tof up to %d interfaces to perform XDP bypass input processing on, "
	"such as\n"
	"\tfor a bond interface one may specify '-i eth0,eth1'.  Note that\n"
	"\tinbound (Internet-facing) interfaces also receive 'tc' outbound\n"
	"\tprocessing in order to rate control/detect attack or unneeded "
	"flow\n"
	"\tpackets.\n"
	"\n"
	"\tMust be specified for -L, along with -o, to get interfaces set up\n"
	"\tproperly.   Is optional for -U, which can use interface map info.\n"
	"\n"
	"    -l, --limit-rates {off|on}\n"
	"\tLimit inbound packet thresholds based on -t|--inbound-pps "
	"settings.\n"
	"\tAlso limit outbound resets based on -m|--max-resets-pps settings.\n"
	"\tRun-time rates/limits are still calculated when 'off' but packet "
	"drops\n"
	"\tover those limits only occurs when 'on'.  Default is '%s'.\n"
	"\n"
	"    -L, --load\n"
	"\t(re)Load XDP and tc eBPF programs, any existing pinned maps "
	"will be\n"
	"\treused.   Any parameter changes are done before the (re)Load, "
	"displays\n"
	"\tof running parameters and/or stats occurs after.\n"
	"\n"
	"\tThere are 3 main (re)Load cases and some subvariants:\n"
	"\n"
	"\t1) Maps not pinned, XDP/tc not running.  Loads and pins will"
	" proceed.\n"
	"\n"
	"\t2) Pinned maps same version as current program's maps.  If  XDP "
	"and\n"
	"\t   tc appear to be running, the -F (force) option must be used "
	"even\n"
	"\t   though the temporary flow disruptions by maps reuse should be\n"
	"\t   inor.   If XDP or tc do NOT appear to be present, new code is\n"
	"\t   Loaded, no disruptions occur in this case.\n"
	"\n"
	"\t3) Pinned maps are NOT the same version as current program's "
	"maps.  In\n"
	"\t   this case the -F (force) option is always required to "
	"proceed as\n"
	"\t   in the previous cases of either minor disruption or just "
	"a code\n"
	"\t   (re)load.  Note it is not advisable to run with such a "
	"maps\n"
	"\t   mismatch, errors may arise unless maps/code carefully "
	"analyzed.  It\n"
	"\t   would be safest to -U (unload/unpin) code/maps first.\n"
	"\n"
	"    -m, --max-resets-pps <packets-per-second>\n"
	"\t<packets-per-second> is the max # of RSTs, ICMPs, etc sent back out "
	"the\n"
	"\tinbound/Internet-facing interface(s).  The default is %dpps.\n"
	"\n"
	"    -M, --monitor-mode {off|on}\n"
	"\tMonitor all processing and stats, do not modify/divert packet "
	"contents\n"
	"\tnor flow. Default is '%s', to modify/divert packet flows.\n"
	"\t'on' is used to enter monitoring mode, all state maintained but "
	"no\n"
	"\tpackets are modified or diverted.\n"
	"\n"
	"    -o, --outbound-ifs <ifname>[,<ifname>...]\n"
	"\tOutput (server-facing) interface to intercept outgoing packets "
	"using\n"
	"\t'tc' toutbound processing.  These are either local packets or "
	"ipvs-sent\n"
	"\tfor initial server-resolution or periodic sample packets.  Without "
	"-R\n"
	"\tinbound (from Internet) packets are normally sent out the"
	" -i interface\n"
	"\tthat received the packet.  With -R the outbound 'tc' resolves the "
	"MAC\n"
	"\tand interface to use for a flow.  '<,ifname>...' is the "
	"comma-separated\n"
	"\tlist of outbound interfaces for a total of up to %d to monitor for\n"
	"\tdirected flows.  Note that the -i and -o interface(s) may be the \n"
	"\tsame.\n"
	"\n"
	"\tMust be specified for -L, along with -i, to get interfaces set up\n"
	"\tproperly.   Is optional for -U, which can use interface map info.\n"
	"\n"
	"    -P, --parameters-display\n"
	"\tDisplay current parameters.   These include modifications made "
	"elsewhere\n"
	"\ton the command line combined with either the built-in defaults "
	"or those\n"
	"\tread in from the pinned parameters map.\n"
	"\n"
	"    -p, --program-array-mode {off|on}\n"
	"\tSpecify whether the program array mode is to be used for the "
	"BPF\n"
	"\tXDP insertion.   Only valid on -L load operations.   The "
	"default is\n"
	"\t'on'.  'off' specifies that XDP should be inserted in driver "
	"mode, or\n"
	"\tSKB mode if -T is specified as well.\n"
	"\n"
	"    -R, --redirect-mode\n"
	"\tRedirect the -i input packets out via the -o output using the "
	"BPF\n"
	"\tRedirect facility. Default is 'off' which is to use the BPF\n"
	"\tXDP_TX to rewrite the -i input packet back out the same "
	"interface.\n"
	"\t'on' will cause BPF redirects for accelerated flows from -i to "
	"-o.\n"
	"\tThe -o interface used is that chosen by ipvs/networking for the "
	"initial\n"
	"\tpacket(s) of the flow.\n"
	"\n"
	"    -r, --inactive-seconds-xdp <inactive_seconds>\n"
	"\t<inactive_seconds> is the number of seconds of idle since prior "
	"packet\n"
	"\tarrival to force re-resolution via ipvs of latest packet of this \n"
	"\tflow.  The default is %d seconds, range 1-900.   Must be less than "
	"the\n"
	"\tipvsadm timeout to keep state alive.\n"
	"\n"
	"    -S, --statistics [<secs> [cnt]]\n"
	"\tStatistics for <cnt> displays separated by <secs> seconds "
	"intervals.  If\n"
	"\t<cnt> not specified then continues indefinitely at <secs> "
	"intervals.\n"
	"\tIf neither <secs> nor <cnt> specified, a single set of stats is\n"
	"\tdisplayed along with a sampling of tcp flows if -f was specified.\n"
	"\n"
	"    -s, --sample-seconds-ipvs <sample_seconds>\n"
	"\tNumber of seconds between packets to keep alive ipvs state.\n"
	"\tDefault is %d seconds, range 1-900.  This value must be less than "
	"the\n"
	"\t-r inactivity re-resolution time.\n"
	"\n"
	"    -T, --skb-mode\n"
	"\tUse XDP_FLAGS_SKB_MODE for configurations that do not support "
	"native\n"
	"\tXDP.  This invokes the generic NAPI XDP handling, above the "
	"driver.\n"
	"\tOnly valid on -L load operations.\n"
	"\n"
	"    -t|--inbound-pps <inbound-pps>[+<spike-percent>[+max-percent]]\n"
	"\tThese are the rate parameters for the sum of -i interfaces to "
	"process.\n"
	"\t<inbound-pps> is the total, across all interfaces, of the inbound "
	"packet\n"
	"\tload expected.  The --cpus-rx-rps is used to figure out the per-CPU "
	"rate\n"
	"\tlimiting to perform.  The default inbound rate is %upps.\n"
	"\n"
	"\t+<spike-percent> is the integer percentage, 0-100, beyond the rate "
	"above\n"
	"\tto allow before rate-limiting begins.  The default for this value "
	"is\n"
	"\tto add an additional %d percent.\n"
	"\n"
	"\t+<max-percent> is the integer percent, 0-100, beyond the "
	"<inbound-pps>\n"
	"\trate to index into the highest probability of dropped packets.  "
	"The\n"
	"\tdefault max percentage is %d percent.\n"
	"\n"
	"\tExample for a 2-NIC inbound bond for a targeted rate of 16Mpps "
	"before\n"
	"\tstarting rate limiting.   A 5 percent spike over 16Mpps flows "
	"without\n"
	"\tdrops but random drops will occur beyond that.  The drops will "
	"vary\n"
	"\tlinearly through a near 100 percent drop probability at 50 percent "
	"above\n"
	"\tthe base rate:\n"
	"\t  ... -i eth0,eth1 -a bond0 ... -t 16000000+5+50 ... \n"
	"\tSo this targets 16-16.8Mpps, beyond which rate-limiting begins with "
	"the\n"
	"\tmaximum probability of a packet drop occurring at an arrival rate "
	"of\n"
	"\t24Mpps or higher.\n"
	"\n"
	"    -U, --unload\n"
	"\tUnload XDP and tc eBPF programs, and unpin/delete all maps.  If\n"
	"\tXDP and tc eBPF programs appear to be running, the -F (force)"
	"option\n"
	"\tis required to proceed.  Note if in XDP native driver mode then"
	"the\n"
	"\tXDP programs are 'unloaded' by replacing them with a NOP "
	"XDP eBPF.\n"
	"\tThis is done to avoid NIC ring changes and packet losses.\n"
	"\n"
	"    -v, --vlan <vlan_hdr_tag>\n"
	"\tIf specified, VLAN id 0-4095 to insert into packet before XDP_TX\n"
	"\ttransmit. May be used with -R for the -o output interface or "
	"without\n"
	"\t-R the VLAN header will be applied to the -i input interface "
	"packet\n"
	"\trewrite.  Special value of -1 is used to turn off VLAN tag "
	"support.\n"
	"\n"
	"    -w, --wrap-packets-count <sample-count>\n"
	"\t<sample-count> is the number of packets to process per-CPU "
	"incoming\n"
	"\tbefore taking a measurement of packet arrival rate.  This is used "
	"in the\n"
	"\tsetting of probability to drop subsequent unknown/new packets for "
	"the\n"
	"\tnext period.  The value may be aligned with RX ring size, but need "
	"not\n"
	"\tbe.  The default sample count is %u packets.\n"
	"\n"
	"    -z, --statsd-enable\n"
	"\tSend a small selection of global stats to statsd for display in "
	"marlin\n"
	"\n"
	, RX_CPUS_DEF, XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS, MAX_IN_OUT_INTERFACES
	, xdp_bypass_params_default.limit_rates ? "on" : "off"
	, MAX_FLOW_RESETS_DEF
	, xdp_bypass_params_default.monitor_only ? "on" : "off"
	, MAX_IN_OUT_INTERFACES, INACTIVE_SECS, SAMPLE_SECS
	, TARGET_PPS_DEF, TARGET_PPS_SPIKE_DEF, TARGET_PPS_MAX_DEF
	, WRAP_PACKETS_CNT_DEF);

	exit(EXIT_FAILURE);
}

static int
v4_get_ifaddrs (int ifx, unsigned int * v4_addrs, int numaddrs)
{
	int	count;
	int	fd;
	int	gifaddrs;
	struct	ifconf	ifconf;
	int	ifidx;
	char	ifname[IFNAMSIZ];
	int	ifnamelen;
	struct	ifreq	* ifreqp;
	int	ifreq_size;
	int	ret;

	/* Get name of requested interface, already known to be valid. */
	memset(ifname, 0, sizeof(ifname));
	if (!if_indextoname(ifx, ifname)) {
		printf("*** Interface index %d, unable to find v4 interface. \n"
		, ifx);
		return -1;
	}
	ifnamelen = strlen(ifname);

	/* Need a socket, pick something bogus for protocol. */
	fd = socket(AF_PACKET, SOCK_RAW, ETH_P_LOOPBACK);
	if (fd == -1) {
		perror("socket(AF_PACKET, SOCK_RAW, ETH_P_LOOPBACK) "
		"for SIOCGIFCONF");
		return -1;
	}

	// Size buffer for large chunk of addresses to process, will
	// double it while returned SIOCGIFCONF fills completely.
	ifreq_size = numaddrs * sizeof(struct ifreq);
	ifreqp = NULL;

	// Potentially can take many SIOCGIFCONFs while growing buffer.
	for (;;) {
		ifconf.ifc_req = (struct ifreq *)realloc(ifreqp, ifreq_size);
		ifconf.ifc_len = ifreq_size;
		if (!ifconf.ifc_req) {
			printf("*** SIOCGIFCONF buffer for %ld addresses too "
			"large for realloc on %s addrs, some may be missed.\n"
			, ifreq_size / sizeof(struct ifreq), ifname);
			free(ifreqp);
			close(fd);
			return -1;
                }

		ifreqp = ifconf.ifc_req;

		ret = ioctl(fd, SIOCGIFCONF, (char *)&ifconf);
		if (ret == -1) {
			perror("ioctl(SIOCGIFCONF)");
			free(ifreqp);
			close(fd);
			return -1;
		}

		if (ifconf.ifc_len < ifreq_size)
			break;
		ifreq_size *= 2;
	}

	close(fd);

	count = 0;
	gifaddrs = ifconf.ifc_len / sizeof(struct ifreq);
	for (ifidx = 0 ; ifidx < gifaddrs ; ifidx++) {
		/* Check for AF_INET and interface name(s) matches. */
		if (ifreqp[ifidx].ifr_addr.sa_family != AF_INET)
			continue;

		// Skip interfaces that do not start with the specified name.
		if (strncmp(ifreqp[ifidx].ifr_name, ifname, ifnamelen))
			continue;

		// Do not skip <ifname>:<number> and <ifname>.<vlan> names.
		if (ifreqp[ifidx].ifr_name[ifnamelen] != '\0') {
			// Separator, 1+ digits, and a NULL == 3.
			if (ifnamelen > IFNAMSIZ - 3
			|| (ifreqp[ifidx].ifr_name[ifnamelen] != ':'
			&& ifreqp[ifidx].ifr_name[ifnamelen] != '.'))
				continue;
		}

		if (count >= numaddrs) {
			printf("*** Possibly more than %d local addresses "
			"while procesing interface %s, required local addrs "
			"may be missed. ***\n"
			, numaddrs, ifname);
			free(ifreqp);
			return -1;
		}

		/* Save addr(s) for mainline checks. */
		count++;
		*v4_addrs = ((struct sockaddr_in *)(&ifreqp[ifidx].ifr_addr))
		->sin_addr.s_addr;
		v4_addrs++;
	}

	free(ifreqp);
	return count;
}

static int
v6_get_ifaddrs (int ifx, struct in6_addr * v6_addrs, int numaddrs) {
	struct in6_addr * addrp;
	unsigned int addr32[4];
	char	bufline[200];
	int	count;
	FILE	* fp;
	int	idx;
	char	ifname[IFNAMSIZ];
	int	ifnamelen;
	char	namestr[IFNAMSIZ];
	int	ret;

	/* Get name of requested interface, already known to be valid. */
	memset(ifname, 0, sizeof(ifname));
	if (!if_indextoname(ifx, ifname)) {
		printf("*** Interface index %d, unable to find v6 interface "
		"name. \n", ifx);
		return -1;
	}
	ifnamelen = strlen(ifname);

	/* All IPv6 interface addresses are in a /proc/net file. */
	fp = fopen("/proc/net/if_inet6", "r");
	if (fp == NULL) {
		printf("Unable to open /proc/net/if_inet6 for IPv6 addrs\n");
		return -1;
	}

	addrp = v6_addrs;
	for (count = 0; count < numaddrs; ) {
		if (!fgets(bufline, sizeof(bufline), fp))
			break;

		/* Check read is long enough for our format string items. */
		bufline[sizeof(bufline) - 1] = '\0';
		if (strlen(bufline) < 53)
			continue;

		/*
		 * Example file line showing where format below comes from:
		 * (128-bit v6 addr, ifindex, prefix, scope, flags, ifname)
		 *
		 * 260628004033019789c53b9f9ad7ae86 02 40 00 21     eth0
		 */
		ret = sscanf(bufline, "%8x%8x%8x%8x %*2x %*2x %*2x %*2x %s"
		, &addr32[0], &addr32[1], &addr32[2], &addr32[3], namestr);
		if (ret != 5) {
			printf("*** Unable to parse ipv6 address line in "
			"/proc/net/if_inet6:\n%s\n\n", bufline);
			fclose(fp);
			return -1;
		}

		// Skip interfaces that do not start with the specified name.
		if (strncmp(namestr, ifname, ifnamelen))
			continue;

		// Do not skip <ifname>.<vlan> names.
		if (namestr[ifnamelen] != '\0') {
			// Separator, 1+ digits, and a NULL == 3.
			if (ifnamelen > IFNAMSIZ - 3
			|| namestr[ifnamelen] != '.')
				continue;
		}

		addrp->s6_addr32[0] = htonl(addr32[0]);
		addrp->s6_addr32[1] = htonl(addr32[1]);
		addrp->s6_addr32[2] = htonl(addr32[2]);
		addrp->s6_addr32[3] = htonl(addr32[3]);

		count++;
		addrp++;
	}

	fclose(fp);

	if (count >= numaddrs) {
		printf("*** %d addrs collected while on interface %s, which "
		"had a remaining allocation limit of %d.\n***  More to check "
		"so may be missing important addresses. ***\n"
		, count, ifname, numaddrs);
		return -1;
	}

	return count;
}
