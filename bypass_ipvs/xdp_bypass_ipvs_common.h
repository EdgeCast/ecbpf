#ifndef XDP_BYPASS_IPVS_COMMON_H
#define XDP_BYPASS_IPVS_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>

// Macro to have correspondence between compilation symbols and quoted strings
#define XBI_QUOTE_SYM(s) XBI_SYM(s)
#define XBI_SYM(s) #s

// Symbol names for compilation of maps and programs.  These symbols are also
// used with the above XBI_QUOTE_SYM macro for character string ELF or BPF
// references.

// Map name symbols
#define	XBI_PARAMS_MAP_NAME	params_map
#define	XBI_STATS_MAP_NAME	stats_map
#define	XBI_TUPLES_MAP_NAME	tuples_map
#define	XBI_INTERFACES_MAP_NAME	interfaces_map
#define	XBI_FWM_MAP_NAME	fwm_map
#define	XBI_V4LADDRS_MAP_NAME	v4laddrs_map
#define	XBI_V6LADDRS_MAP_NAME	v6laddrs_map
#define	XBI_INBOUND_RATES_MAP_NAME	inbound_rates_map
#define	XBI_OUTBOUND_RATES_MAP_NAME	outbound_rates_map

// Program name symbols
#define	XBI_INBOUND_PROG_NAME	xdp_bypass_ipvs
#define	XBI_DUMMY_PROG_NAME	xdp_redirect_dummy_prog
#define	XBI_TC_PROG_NAME	bpf_egress_syn_check

// Number of excluded addresses that may be processed to fit within the
// allocated IPv4 and IPv6 local address maps.  See notes on hash maps below
// for option to remove this fixed restriction.
#ifndef XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS
#define XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS 64
#endif

/*
 * Map key for established 4-tuple (TCP) flows to bypass ipvs processing and
 * be directed to the specified destination.
 *
 * Note: Local/Remote naming of fields is used instead of Source/Destination
 * packet fields so as to make the code clearer for key setup which packet
 * fields goes into which key field based on the direction the code is handling.
 *
 */
typedef struct xdp_bypass_4tuple {
	union {
		__u32 v6[4];
		__u32 v4;
	} raddr;		// packet saddr on inbound, daddr on outbound.
	union {
		__u32 v6[4];
		__u32 v4;
	} laddr;		// packet daddr on inbound, saddr on outbound.
	__u16	rport;		// packet sport on inbound, dport on outbound.
	__u16	lport;		// packet dport on inbound, sport on outbound.
	char	family;		// AF_INET[6]
	char	pad[11];	// Pad to 16-byte multiple.
} xdp_bypass_4tuple_t;

// Value of destination interface and MAC to use for four-tuple key in the
// LRU tuples map.
typedef struct xdp_bypass_dest_intf {
	int	ifindex;	/* As selected by ipvs on raw socket */
	int	use_xdp_tx;	/* Do not redirect, use XDP_TX on same NIC */
	__u32	vlan_tag;	/* VLAN tag/header to use, if non-zero */
	unsigned char eth_daddr[ETH_ALEN];
	unsigned char eth_saddr[ETH_ALEN];	/* Avoids per-pkt map lookup */
	long	pkts_bypass;	/* Packets transmitted directly from XDP */
	long	pkts_outbound;	/* Packets sent out via ipvs sampling */
	__u64	last_activetime;	/* Last time active in nanoseconds */
	__u64	last_ipvstime;	/* Last time up to ipvs in nanoseconds */
	__u64	prev_ipvstime;	/* Previous last time to ipvs in nanoseconds */
	int	fin_seen;	/* A FIN sent upstream to ipvs */
	int	resolved;	/* Destination ethernet ready for use */
	int	creation_cpu;	/* CPU this entry was first created on */
	int	resolve_delay;	/* This flow experienced resolution delay */
	int	rst_sent_out;	/* Outbound code has sent RSTs, flow dead. */
} xdp_bypass_dest_intf_t;

// Per-CPU RST rate limiting to prevent spending excess cycles on needless
// redundant RST sending.  Basically each outgoing CPU (which may be the same
// as an inbound processing one, depending upon IRQ/RPS layout) tracks its own
// quota and rates of RSTs.   So assuming a reasonably-spread hashing, the
// rate limits are chosen so the aggregate is still a low rate of emitted
// RSTs.
//
// Accessed only by TC or XDP outbound processing on a per-CPU basis, so no need
// for locking/synchrony on field updates.
typedef struct	tc_outbound_rates {
	__u64	rsts_discarded;	// Total RSTs discarded, rate limited.
	__u64	start_time_ns;	// Start time of epoch.
	__u64	end_time_ns;	// End time of epoch, do simple reset for now.
	int	rsts_sent;	// In current epoch.
} tc_outbound_rates_t;

// The interfaces map is keyed by the interface index and contains the hardware
// address as well as some configuration flags.  It is used by the (deprecated)
// BPF_REDIRECT code as well as to inform the "tc" packet processing.   This
// map is set up by the user space and not modified.
#define	TC_MAX_LINKS	64	// Large enough to handle non-linear indicies.

#define	TC_INTF_F_INTERNET	0x01	// Internet-facing.
#define	TC_INTF_F_INSIDE	0x02	// Non-Internet, ipvs & inside checks.
#define	TC_INTF_F_BYPASS	0x04	// Explicitly for bypass addresses.

typedef struct	tc_interface_info {
	int	if_flags;	// Internet or inside interface, may be both.
	unsigned char hwaddr[ETH_ALEN];
} tc_interface_info_t;

// Values of rates info for inbound flow packets on inbound interfaces as a
// per-CPU array keyed by CPU number.   Note that there is a single version of
// this map/struct for all XDP interfaces on a CPU.  Since multiple rings on a
// single CPU are handled serially these parameters can be updated without
// synchronization concerns.  However it should be kept in mind that the "wrap"
// at which the rate-limits are applied is a combination of multiple interfaces'
// inputs (bonds?) and not necessarily a ring size.
//
// This map/struct is used exclusively by inound XDP processing, with each
// CPU that may handle a set of RX IRQs having its own struct element.   So
// there is no need for locking/synchrony, unless an issue arises for user-space
// stats fetching (then perhaps a second copy, one wrap old, could be kept
// consistent at low cost)..
//
// TOCONSIDER: Combine inbound and outbound rate maps into a single per-CPU map
// that contains both the above tc_outbound_rates_t and xdp_inbound_rates_t
// structures.
typedef struct	xdp_inbound_rates {
	__u64	ltime_wrap_ns;	// Time of last ring wrap.
	int	curr_pkts;	// Inbound packets since last calculation
	int	curr_prob_idx;	// Probability of keeping, until next wrap.
	// Remaining items are stats that are not referenced|updated per-packet.
	__u64	min_wrap_ns;	// Smallest (fastest) ring wrap duration ns.
	__u64	max_wrap_ns;	// Largest (slowest) ring wrap duration ns.
	__u64	in_discards;	// Unknown flow pkts dropped above threshold.

	__u64	last_wrap_ns;	// Duration of last/latest ring wrap ns/
				// TOCONSIDER: Moving/smooth average for stats?
} xdp_inbound_rates_t;

/*
 * XDP operational parameters, settings, etc.  These are supplied from user
 * space program to the kernel via a global array map, with only element zero
 * of that array containing this structure.  Its treated as read-only by the
 * kernel eBPF code.
 */
#define	XBI_PARAMS_PROB_256 (16)

typedef struct xdp_bypass_params {
	__u64	inactive_nsecs;	// Nanoseconds to force flow re-resolution.
	__u64	sample_nsecs;	// Sample time for ipvs in nanoseconds.
	int	monitor_only;	// Do all processing/stats, but XDP_PASS all.
	int	use_xdp_tx;	// XDP_TX on same NIC, otherwise bpf redirect.
	int	vlan_hdr_tag;	// If >= 0, tag/header to use.
	char	map_header_sha256[65];  // 64 bytes, null-terminated.
	int	mode_progarray;	// In program array mode, not NIC driver or SKB.
	int	limit_rates;	// Do inbound/outbound limits per rate settings.
	__u32	out_rsts;	// per-CPU RSTs in epoch to cap at.
	__u64	out_rsts_epoch_ns; // per-CPU RSTs in epoch time in ns.
	__u64	wrap_target_ns;	// Targeted time to wrap count, from pps rate.
	__u64	wrap_min_ns;	// Faster than target mark, start rate control.
	__u32	in_wrap_cnt;	// Inbound samples to time.  May be ring size.

	__u16	prob_256[XBI_PARAMS_PROB_256];	// Probability lookup array,
				// based on a random integer that is some
				// fraction of 256 to provide the appropriate
				// probability of a packet being kept or
				// dropped.  Is indexed by a function of a
				// divisor (below) for the amount of
				// bandwidth/rate over the target.  Used by
				// every inbound packet that is unknown when the
				// current sample period is over the target
				// rate.   Dropping the packet saves the
				// allocation of possibly unneeded state
				// information, such as SYN or ACK attack
				// packets at high rates.

	__u32	prob_divisor;	// Chosen to deal with the expected ranges of
				// time/rate so the maximum handled rate falls
				// at the end (highest drop, least kept) slot
				// of the probability array.  Used once per
				// sample period.

	// The following user space parameters are for persistence between user
	// space invocations so the inputs to these and the above values passed
	// to the kernel/eBPF code are preserved.  This allows parameters to be
	// queried as well as modified dynamically by the user space code
	// across invocations.
	__u16	rx_cpus;	// Inbound packet-receiving (XDP process) CPUs.
	__u16	rps_cpus;	// Outbound packet-processing CPUs.
	__u32	inbound_pps;	// Inbound pps before (random) rate limiting.
	__u32	inbound_spike;	// Integer percent/range to allow without limit.
	__u32	inbound_max;	// Percent max rate to handle, likliest to drop.
	__u32	max_reset_pps;	// Outbound resets/rejects before rate limits.
} xdp_bypass_params_t;

/*
 * Global stats map.  As the parameters map did, this structure is in an array
 * map with the zero'th element simply being this structure.   But this 1
 * element array is a per-CPU array so the stats may be safely updated without:
 * locking, RCU usage, nor the atomic/sync update overheads.
 *
 * User space must aggregate for global stats across all CPUs that created
 * non-zero values.  That is expected to be primarily the RX softirq CPUs,
 * which is where the XDP/eBPF kernel code is invoked.  An important rule here,
 * which user space enforces, is that every item must be a 64-bit entity due to
 * the array aggregation method employed by user space to simplify code
 * maintenance.
 */
typedef struct xdp_global_stats {
	__u64	total_pkts_xdp_rx;	// All packets presented to XDP eBPF.
	__u64	total_pkts_tc_tx;	// All packets presented to TC eBPF.
	__u64	total_bypassed_pkts;	// Packets bypassed ipvs processing.
	__u64	lru_alloc_map_tuples;	// Total, doesn't reduce by LRU cleanup.
	__u64	ipv4_pkts;
	__u64	ipv6_pkts;
	__u64	ipv4_inbound_locals;	// Locally-destined packets.
	__u64	ipv6_inbound_locals;	// Locally-destined packets.
	__u64	tcp_pkts;
	__u64	broad_multi_pkts;	// Broad/Multicast packets passed.
	__u64	lru_alloc_syns;		// SYN TCP, new lru entry.  Expected.
	__u64	lru_reuse_syns;		// SYN TCP, old lru entry.  Expected.
	__u64	lru_deletion_RST;	// RST in, delete LRU (do not create).
	__u64	lru_deletion_out_RST;	// RSTs outbound, delete LRU.
	__u64	lru_alloc_nonsyns;	// Non-SYN, new lru entry.  Expect few.
	__u64	lru_reuse_nonsyns;	// Non-SYN, old lru entry.  Expected.
	__u64	lru_miss_out_syn;	// SYN outbound, no lru.  Can be ok.
	__u64	lru_miss_out_nonsyn;	// Non-SYN out, no lru.  Can be ok.
	__u64	lru_miss_in_limited;	// No lru inbound, rate limited drop.
	__u64	out_rsts_sent_tc;	// Out RSTs sent, from tc/ipvs.
	__u64	out_rsts_sent_xdp;	// Out RSTs sent, from XDP.
	__u64	out_rsts_disc_rate;	// Out RSTs discarded, rate limited.
	__u64	out_rsts_disc_flow;	// Out RSTs discarded, flow limited.
	__u64	out_rsts_unknown;	// Out RSTs sent, no tuple state.
	__u64	in_rsts_disc_flow;	// In RSTs discarded, flow state.
	__u64	resolution_pending;	// LRU not yet resolved for packet.
	__u64	inactivity_timeout;	// Inactive LRU to be re-resolved.
	__u64	resolution_drops;	// Pkts dropped due to no resolution.
	__u64	resolution_failed;	// Invalid interface, config error?
	__u64	lru_res_delayed;	// Many pkts with no resolution (yet).
	__u64	lru_res_delayed_fixed;	// Delayed resolution finally fixed.
	__u64	lru_res_reuse_fix;	// Re-resolution eventually fixed.
	__u64	ipv4_fragmented_pkts;	// These are just passed.
	__u64	lru_fail_map_tuples;	// Failure on map tuple allocation.
	__u64	ipv4_outbound_local_marked; // Marked outbounds.  Unusual!
	__u64	frame_errors;		// Unable to parse/process packet.
	__u64	adjust_head_errors;	// Unable to slide down ethernet.
	__u64	unknown_interface;	// Pkt ifindex refs unknown interface.
	__u64	suspect_misflows_sack;	// Unknown/misdirected flows yet SACK.
	__u64	unexpected_ipvs_rsts;	// RST despite recent packet up to ipvs.
} xdp_global_stats_t;

#ifdef XDP_BYPASS_IPVS_KERNEL_EBPF
// Miscellaneous items needed for kernel eBPF builds

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

/* Replicated, libbpf build does not include kernel linux/if_vlan.h structs */

/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

/*
 * libbpf, as opposed to kernel tree, doesn't define these.  Replicated here
 * from bpf_helpers.h under kernel tree tools/testing/selftests/bpf.
 */
unsigned long long load_byte(void *skb, unsigned long long off)
	asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off)
	asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off)
	asm("llvm.bpf.load.word");

/* Compile-time override for experiments or limited virtual test configs. */

// TOCONSIDER: Due to an overzealous "tc" max_entries map verification test
// on pinned maps a VERY careful value has to be chosen that the kernel will
// not "round up" to run afoul of those "tc" checks kicking out the map
// object loading.   To avoid the rounding, the number of entries has to be
// an even multiple of the total number of CPUs on the system.  To account for
// all our CPUs models, we multiply them all together and/or choose the least
// common multiple to come up with.  Currently: 72*40*32*24 (2211840) or
// use the lowest common multiple 1440 (that all our CPU models divide into)
// as the factor in defining the number of entries.  For finer-grain setting of
// the number of entries the later is used here.  These values also happen
// to work for a 96 CPU system, one of the potential candidate platforms at
// time of this writing.
#ifndef	XDP_BYPASS_IPVS_TUPLES_MAX
#define	XDP_BYPASS_IPVS_TUPLES_MAX ((20000000/1440 + 1) * 1440)
#endif

// Kernel eBPF maps used by XDP and many by TC eBPF as well. The
// later TC loading process also pins ALL maps, whether used by tc or not,
// but for the TC loading process to do the pinning (or non-default map BPF FS
// location) requires a "compatibly extended" version of the map definition
// struct as defined below by bpf_elf_map.   BUT...
//
// ... for the XDP eBPF program to be inserted into the root program array along
// with the xdpcap functionality requires additional maps beyond those used
// by the mainline bypass ipvs code.   These additional maps are defined using
// the standard BPF map definition but its not valid to intermix different
// ELF map definitions in the same kernel .o file.   SO....
//
// ... the following defines a macro that permits a single definition of each
// required XDP and TC map but is being defined to generate either the standard
// map struct (for XDP) or the iproute2's "loader" version (for TC).   As long
// as the map CONTENTS: the keys, values, and BPF flags are the same ; then
// the kernel tc's .o map extensions are moot.

#ifdef	XDP_BYPASS_IPVS_IPROUTE2_MAPS

#ifdef focal
// From bpf_elf.h iproute2 loader for use with tc and other iproute2 utilities when under FOCAL.
struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
        __u32 inner_id;
        __u32 inner_idx;
};

/* Object pinning settings in BPF filesystem from bpf_elf.h for tc "loader". */
#define PIN_NONE       0
#define PIN_OBJECT_NS  1
#define PIN_GLOBAL_NS  2

// Invoke extended map definition for TC/iproute2 style of kernel maps for FOCAL
// Add a pinning value for IPROUTE2 maps
//
#define        XDP_BYPASS_IPVS_MAP_STRUCT(name,mtype,keysz,valuesz,entries,mflags) \
struct bpf_elf_map SEC("maps") name = { \
       .type = mtype, \
       .size_key = keysz, \
       .size_value = valuesz, \
       .max_elem = entries, \
       .flags = mflags, \
       .pinning = PIN_GLOBAL_NS }

#else

// Add a pinning value for IPROUTE2 maps and use BTF for Jammy and newer
//
#define	XDP_BYPASS_IPVS_MAP_STRUCT(name,mtype,keysz,valuesz,entries,mflags) \
struct { \
	__uint(type, mtype); \
	__uint(key_size, keysz); \
	__uint(value_size, valuesz); \
	__uint(max_entries, entries); \
	__uint(map_flags, mflags); \
	__uint(pinning, LIBBPF_PIN_BY_NAME); \
} name SEC(".maps")

#endif // focal
#else // Standard BPF map kernel definition for non-iproute2 maps

#define	XDP_BYPASS_IPVS_MAP_STRUCT(name,mtype,keysz,valuesz,entries,mflags) \
struct { \
	__uint(type, mtype); \
	__uint(key_size, keysz); \
	__uint(value_size, valuesz); \
	__uint(max_entries, entries); \
	__uint(map_flags, mflags); \
} name SEC(".maps")

#endif // XDP_BYPASS_IPVS_IPROUTE2_MAPS

// Now define all the common maps for both XDP and TC, using appropriate struct.

/*
 * Operational parameters, settings, etc.  A simple array to use globally
 * with a single entry within, at the zero'th element.
 */
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_PARAMS_MAP_NAME,	\
	BPF_MAP_TYPE_ARRAY,	\
	sizeof(__u32),	\
	sizeof(xdp_bypass_params_t),	\
	1,	\
	0);

/*
 * Global statistics.   A simple array to use globally with a single
 * record structure for all the main stats, at the zero'th element.  For
 * performance this array is allocated per-cpu, with the user application
 * doing the collection/summary.  In testing at the 12+Mpps rates using per-cpu
 * gave 150-300Kpps improvement on 8 IRQ CPUs on a G7.
 */
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_STATS_MAP_NAME,	\
	BPF_MAP_TYPE_PERCPU_ARRAY,	\
	sizeof(__u32),	\
	sizeof(xdp_global_stats_t),	\
	1,	\
	0);

// Use LRU for the tuples map so as to avoid explicit garbage collection.
//   XDP_BYPASS_IPVS_TUPLES_MAX entries compile-time.
//   TOCONSIDER: Make above modifiable at load/pin time?
//   BPF_F_NUMA_NODE incompatible with BPF_F_NO_COMMON_LRU flag, affinitize
//   loader to appropriate CPU.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_TUPLES_MAP_NAME, \
	BPF_MAP_TYPE_LRU_HASH,	\
        sizeof(xdp_bypass_4tuple_t),	\
        sizeof(xdp_bypass_dest_intf_t),	\
        XDP_BYPASS_IPVS_TUPLES_MAX,	\
	BPF_F_NO_COMMON_LRU);

// ifindex'ed map to provide the MAC hardware address for each interface
// as well as some flags.   And possibly additional interface-specific settings
// in the future
//
// This map is used for the redirect handling case (deprecated), as well as
// the "tc" outbound packet handling for RSTs or other flow-terminating
// indications.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_INTERFACES_MAP_NAME,	\
	BPF_MAP_TYPE_ARRAY,	\
	sizeof(__u32),	\
	sizeof(tc_interface_info_t),	\
	TC_MAX_LINKS,	\
	0);

/* Counters map on outbound interface to track new flows by firewall mark. */
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_FWM_MAP_NAME,	\
	BPF_MAP_TYPE_ARRAY,	\
	sizeof(__u32),	\
	sizeof(long),	\
	256,	\
	0);

// HASH maps for interface addresses and local-only service addresses/VIPs.
// The number of map elements is defined here so user and kernel coordinate
// on the number of acceptable interface and local-service addresses.
//
// TOCONSIDER:  Try BPF_F_NO_PREALLOC for assigning # max hash buckets, table
// should grow up to memory limits.  "tc" loader SHOULD not object to the flag.

// Hash key is IPv4 local address and the single u32 value of TRUE indicates
// the associated address is from a configured interface.   Else it has been
// explictly configured to be excluded from fastpath processing.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_V4LADDRS_MAP_NAME,	\
	BPF_MAP_TYPE_HASH,	\
	sizeof(__u32),	\
	sizeof(__u32),	\
	XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS,	\
	0);

// Hash key is IPv6 local address and the single u32 value of TRUE indicates
// the associated address is from a configured interface.   Else it has been
// explictly configured to be excluded from fastpath processing.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_V6LADDRS_MAP_NAME,	\
	BPF_MAP_TYPE_HASH,	\
	4 * sizeof(__u32),	\
	sizeof(__u32),	\
	XDP_BYPASS_IPVS_EXCLUDE_NUMADDRS,	\
	0);

// Per-CPU map for the inbound rates collection in the XDP RX IRQ processing.
// There is just a single entry for each CPU.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_INBOUND_RATES_MAP_NAME, \
	BPF_MAP_TYPE_PERCPU_ARRAY,	\
        sizeof(__u32),	\
        sizeof(xdp_inbound_rates_t),	\
        1,	\
	0);

// Per-CPU map for the outbound rates collection in 'tc' and 'xdp' Internet
// processing.  There is just a single entry for each CPU.
XDP_BYPASS_IPVS_MAP_STRUCT(XBI_OUTBOUND_RATES_MAP_NAME, \
	BPF_MAP_TYPE_PERCPU_ARRAY,	\
        sizeof(__u32),	\
        sizeof(tc_outbound_rates_t),	\
        1,	\
	0);

#endif // XDP_BYPASS_IPVS_KERNEL_EBPF
#endif // XDP_BYPASS_IPVS_COMMON_H
