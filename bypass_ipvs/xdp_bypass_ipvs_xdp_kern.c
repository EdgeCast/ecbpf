/*
 * ipvs bypass ("ACK accelerator" or just "fastpath") consists of a user
 * space map/code loader and parameter/control settings ; the XDP eBPF inbound
 * component ; and the TC eBPF outbound component.

 * ipvs bypass utilizes kernel components consisting of loaded XDP and TC eBPF
 * programs to look for inbound flows that have already been established by
 * the kernel ipvs module to be redirected out to a specific destination
 * interface and MAC address of a real server.  By having the XDP component
 * forward packets directly on to the destination server a lot of kernel
 * iptables and ipvs processing is skipped for that flow.
 *
 * The XDP inbound component described here and contained in the code below
 * may be installed in the system one of 3 separate points: NIC drivers with
 * XDP support for invoking eBPF on packets still in their RX ring buffers ;
 * lower performance SKB/generic for NIC drivers which don't have XDP support
 * directly so the kernel has a "hook point" for processing incoming packets
 * once they have been moved into SKBs ; or a "program array" associated with
 * a particular driver/NIC that retains almost all of the performance of the
 * first point but allows flexibility to swap/stack multiple XDP programs.  
 * This last one is the desired deault since it allows us to have a single
 * "root" XDP program on the driver/NIC itself that stays attached to the
 * driver for the life of the system.   That "root" in turn allows the XDP
 * programs, such as the one below, to be called in turn/order for each packet
 * in the RX rings and that set of XDP programs can be removed/inserted/updated
 * at any time without perturbing the driver/NIC configuration or packet flows.
 * The point at which the XDP program is attached is set by the user space
 * loader's command line options.
 *
 * The TC eBPF outbound component is associated with the outbound interface(s)
 * specified to the user space loader program.  Depending upon the system
 * configuration that outbound interface may or may not be the same as the
 * interface that the XDP program is installed on.  Note that the TC eBPF is
 * now associated with BOTH the "outbound to server" interface(s) as well as the
 * "Internet facing" (inbound) interface(s).  The later is now required to
 * detect RSTs (or other non-recoverable errors) on flows so the XDP portion
 * may be signalled for greater efficiency on dropping no-longer-valid packets.
 *
 * The remaining commentary applies to the entire set of programs but the code
 * below is only for the XDP eBPF component.   See the related "tc_kern" file
 * for the TC eBPF code.
 *
 * A global LRU map of TCP tuples is managed by each receiving XDP eBPF using
 * the "no common LRU" option.  RPS and other CPUs may then examine and do
 * atomic updates without fear of RCU synchronization overheads.  The LRU
 * entry is made by the XDP program upon discovery of a new flow not in the
 * the table (or previously LRU'ed out).  To obtain the "address resolution"
 * of where to send the initial packet as well as its followers, the packets
 * are sent onward into the kernel for standard iptables and ipvs processing.
 * The "resolution" occurs when ipvs selects a server and sends the packet out.
 *
 * Once ipvs (or any application on the system) sends a packet out, the
 * interface-bound "tc" egress eBPF program gets an oppportunity to inspect the
 * packet and skb fields.  (Currently, a system("tc") is run by the user space
 * program to both load the "classifier" eBPF program in the associated tc eBPF
 * code to see all exiting packets, as well as to pin maps at load time.) If
 * the packet has been firewall marked it is looked up in the LRU table for the
 * previously established entry created by the XDP portion.  If address
 * resolution has not yet occurred then the outgoing interface (if selected) is
 * chosen and the destination ethernet address recorded for subsequent entries.
 * If address resolution has already occurred, then only statistics are updated.
 *
 * The above "tc" description applies to the "server facing" (outbound) handling
 * of packets but there is also code that monitors the outgoing rate of RSTs
 * or other errors (someday) back to the Internet (inbound) interface.  RSTs
 * are rate-limited by both an aggregate, specified packets-per-second for the
 * system as a whole (done with per-CPU quotas) as well as limited by the
 * individual flows (no need for a single flow to get more than a few RSTs to
 * assure reliabile client notification).  This improves performance in several
 * dimensions (local CPU and driver/network as well as entire path back to the
 * client's CPU and network).
 *
 * On the above rate-limiting, note that once XDP inbound handling has been
 * signalled it also applies outgoing RST limiting so as to most efficiently
 * dispose of such packets right at the driver.  Or, instead of disposing the
 * incoming, to transform them into RSTs back to the client.
 *
 *
 * Miscellaneous details/issues/futures:
 *
 *   IPv6, UDP, and QUIC are not currently handled.   Only IPv4/TCP will get
 *   the bypass treatment, all others will be handled as they are today.
 *
 *   Once the above state is set up for a flow, a small percentage of packets
 *   continue to be forwarded upstream towards ipvs to keep its state active
 *   so it doesn't time out.  It is likely that in a high rate of ACKs this
 *   will cause one to be significantly reordered but this should have no
 *   impact.   For data packets its possible a reordering could trigger a
 *   false "loss detection" so a means to try and delay such reordering until
 *   an ACK would be desirable.   No means of detecting this for UDP or QUIC
 *   when/if support is added for those.
 *
 *   Note that above reordering may have a totally different characteristic
 *   when running in a mode compatible with today's directors, where the
 *   sampled/reordered packet will exit via a different interface, than the
 *   eventual approach which would have all interfaces on one bond.
 *
 *   The bpf redirect via index or the maps have proven to be slow (so far) and
 *   the preferred mode is to rewrite packets out the same interface.  This
 *   implementation now can add a vlan tag/header to accomplish this while
 *   retaining current director configurations, at least for initial monitoring
 *   or testing.  The ipvs bypass user space program may be configured to pass
 *   that info down to the XDP program via a map.  The support is now in place
 *   for all the director interfaces to be in bond(s) and the physical device
 *   will always get the same packet out that came in, just rewritten to the
 *   correct ethernet address (and VLAN, if specified).
 *
 *   A new form of DDOS defense has been implemented based on setting a target
 *   inbound threshold from the Internet interface(s) and then applying a
 *   degree of probability to drop that packet based on the amount the target
 *   threshold has been exceeded.  Note that this logic applies to new flows or
 *   idle flows that aged out from the LRU map.
 */
#define ECBPF_KERN
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <netinet/ip6.h>
#include <linux/pkt_sched.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#define	XDP_PROG_ARRAY_IDX XDP_IPVS_BYPASS_IDX
#include <libecbpf_kern.h>
#define	XDP_BYPASS_IPVS_KERNEL_EBPF
#include "xdp_bypass_ipvs_common.h"

// Unable to use standard Linux kernel headers so checksum macros copied
// here from asm and generic checksum.h includes.
typedef __u16 __be16;
typedef __u16 __sum16;
typedef __u32 __be32;
typedef __u32 __wsum;

static inline __sum16 csum_fold(__wsum csum)
{
	__u32 sum = (__u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static inline __wsum csum_unfold(__sum16 n)
{
	return (__wsum)n;
}

static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	__u32 res = (__u32)csum;
	res += (__u32)addend;
	return (__wsum)(res + (res < (__u32)addend));
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	__u16 res = (__u16)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__wsum tmp = csum_sub(~csum_unfold(*sum), (__wsum)from);

	*sum = csum_fold(csum_add(tmp, (__wsum)to));
}

/*
 * XDP function invoked on inbound interface packets to redirect to an outbound
 * interface if they are in the established four-tuple map.   The outbound
 * interface and destination MAC address are established by the tc filter
 * eBPF program installed at the "egress" hook point of the outbound interface.
 */
SEC("xdp")
int XBI_INBOUND_PROG_NAME(struct xdp_md *ctx)
{
	__u32	* addr_valuep;
	int	cpunum;
	__u64	curr_time_ns;
	void	* data;
	void	* data_end;
	int	delayval;
	struct ethhdr * eth;
	xdp_inbound_rates_t * inboundp;
	int	index;
	struct iphdr * iph;
	__u64	last_activetime_ns;
	__u64	last_ipvstime_ns;
	xdp_bypass_params_t * paramsp;
	uint	prob_idx;
	xdpcap_retval_t	ret_status = {XDP_PASS, XDP_CODE_MU, 0x00};
	xdp_global_stats_t * statsp;
	struct tcphdr * tcph;
	xdp_bypass_4tuple_t	tuple_key;
	xdp_bypass_dest_intf_t	tuple_value;
	xdp_bypass_dest_intf_t * tuple_valuep;
	long	* valuep;
	struct vlan_ethhdr * veth;
	__u64	wrap_ns;

	/* Get pointers to critical parameters and stats that MUST be there. */
	index = 0;
	paramsp = bpf_map_lookup_elem(&XBI_PARAMS_MAP_NAME, &index);

	// These per-CPU maps only have a single entry.
	statsp = bpf_map_lookup_elem(&XBI_STATS_MAP_NAME, &index);
	inboundp = bpf_map_lookup_elem(&XBI_INBOUND_RATES_MAP_NAME, &index);

	if (!paramsp || !statsp || !inboundp) {
		int fwm = 0;
		/*
		 * Give up, not much to do here on this impossible(?) case.
		 * Slam the zeroth element with a -1 to indicate we are not
		 * running/processing any packet flows.
		 */
		valuep = bpf_map_lookup_elem(&XBI_FWM_MAP_NAME, &fwm);
		if (valuep)
			*valuep = -1;
		// May not have parameters to determine mode, just return
		// since something is wrong with the map(s).
		return XDP_PASS;
	}

	statsp->total_pkts_xdp_rx++;

	/* Packet limits. */
	/* TODO: Later kernels have metadata with queue/ifindex info. */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Addressability of ethernet frame */
	eth = data;
	if (&eth[1] > data_end) {
		statsp->frame_errors++;
		goto NEXT_PROG_OR_PASS;
	}

	/* Not processing broadcast/multicast */
	if (eth->h_dest[0] & 1) {
		statsp->broad_multi_pkts++;
		goto NEXT_PROG_OR_PASS;
	}

	/* Non-IPv4 processing */
	/* TODO: Add in IPv6 handling, break into inlines for clarity? */
	if (eth->h_proto != ntohs(ETH_P_IP)) {
		if (eth->h_proto == ntohs(ETH_P_IPV6))
			statsp->ipv6_pkts++;
		goto NEXT_PROG_OR_PASS;
	}

	statsp->ipv4_pkts++;

	/* Validate full IP header present. */
	iph = (struct iphdr *)&eth[1];
	if (&iph[1] > data_end || iph->version != 4
	|| iph->ihl < (sizeof(struct iphdr) >> 2)) {
		statsp->frame_errors++;
		goto NEXT_PROG_OR_PASS;
	}

	/* Only handling TCP currently, and non-fragmented at that. */
	if (iph->protocol != IPPROTO_TCP)
		goto NEXT_PROG_OR_PASS;

	statsp->tcp_pkts++;

	if ((~ntohs(IP_DF) & iph->frag_off) != 0) {
		statsp->ipv4_fragmented_pkts++;
		goto NEXT_PROG_OR_PASS;
	}

	// Account for IP options to locate TCP header, just in case.
	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	if (&tcph[1] > data_end) {
		statsp->frame_errors++;
		goto NEXT_PROG_OR_PASS;
	}

	/* Lookup the flow tuple, set up the key all in network order. */
	memset((void *)&tuple_key, 0, sizeof(tuple_key));
	tuple_key.raddr.v4 = iph->saddr;
	tuple_key.laddr.v4 = iph->daddr;
	tuple_key.rport = tcph->source;
	tuple_key.lport = tcph->dest;
	tuple_key.family = (eth->h_proto == ntohs(ETH_P_IP))
	? AF_INET : AF_INET6;

	// Fetch time for flow activity measures and inbound rate calculations.
	curr_time_ns = bpf_ktime_get_ns();
	inboundp->curr_pkts++;
	if (inboundp->curr_pkts > paramsp->in_wrap_cnt) {
		// Take measurement of this "wrap" time, set keep/drop index
		wrap_ns = curr_time_ns - inboundp->ltime_wrap_ns;
		if (wrap_ns >= paramsp->wrap_min_ns) {
			// In targeted range, "keep" is set to 100% bucket.
			prob_idx = 0;
		} else {
			// Index to higher probabilities of drop with time/rate.
			prob_idx = (paramsp->wrap_target_ns - wrap_ns)
			/ paramsp->prob_divisor;
			if (prob_idx >= XBI_PARAMS_PROB_256)
				prob_idx = XBI_PARAMS_PROB_256 - 1;
		}

		// Settings for next sample's worth of packets and stats.
		if (!inboundp->min_wrap_ns || wrap_ns < inboundp->min_wrap_ns)
			inboundp->min_wrap_ns = wrap_ns;
		else if (!inboundp->max_wrap_ns
		|| wrap_ns > inboundp->max_wrap_ns)
			inboundp->max_wrap_ns = wrap_ns;
		inboundp->last_wrap_ns = wrap_ns;

		inboundp->ltime_wrap_ns = curr_time_ns;
		inboundp->curr_pkts = 0;
		inboundp->curr_prob_idx = prob_idx;
	}

	// Lookup tuple, create or update if not yet existing or resolved.  Do
	// not create, and possibly delete, if this has been RST outbound.
	tuple_valuep = bpf_map_lookup_elem(&XBI_TUPLES_MAP_NAME, &tuple_key);
	if (!tuple_valuep) {
		unsigned char * curroptp;
		unsigned int	sack_offset;

		/* Just pass v4 destinations listed in the locals map. */
		addr_valuep = bpf_map_lookup_elem(&XBI_V4LADDRS_MAP_NAME
		, &tuple_key.laddr.v4);
		if (addr_valuep && *addr_valuep) {
			statsp->ipv4_inbound_locals++;
			goto NEXT_PROG_OR_PASS;
		}

		// No tuple inbound nor threshold-reached outbound RST entry,
		// random discard if probability index indicates.
		if (inboundp->curr_prob_idx) {
			int	keep;
			uint	curr_prob_idx;

			curr_prob_idx = inboundp->curr_prob_idx;
			// Can not happen above, eBPF verifier needs this check.
			if (curr_prob_idx >= XBI_PARAMS_PROB_256)
				curr_prob_idx = XBI_PARAMS_PROB_256 - 1;
			keep = ((__u16)(bpf_get_prandom_u32() & 0xff)
			<= paramsp->prob_256[curr_prob_idx])
			? 1 : 0;
			if (!keep) {
				statsp->lru_miss_in_limited++;
				inboundp->in_discards++;
				// Do not drop if in monitor mode or rate
				// limiting not enabled.  But all stats and
				// calculations are updated as if a drop did
				// occur, for evaluation purposes.
				if (!paramsp->monitor_only
				&& paramsp->limit_rates) {
					ret_status.action = XDP_DROP;
					goto XDPCAP_RETURN_WITH_STATUS;
				}
			}
		}

		/* Do not create an LRU for resets(!), just pass. */
		if (tcph->rst) 
			goto NEXT_PROG_OR_PASS;

		/* Create entry which will await outgoing resolution. */
		memset((void *)&tuple_value, 0, sizeof(tuple_value));

		// FIN indicates that more frequent alerts to ipvs are needed.
		if (tcph->fin)
			tuple_value.fin_seen = 1;

		/* Initialize timestamps */
		tuple_value.last_activetime = curr_time_ns;
		tuple_value.prev_ipvstime = curr_time_ns;
		tuple_value.last_ipvstime = curr_time_ns;

		/* If use_xdp_tx mode, take this opportunity to record saddr. */
		/* TODO: Can fix with later kernels and XDP ifindex metadata. */
		if (paramsp->use_xdp_tx)
			memcpy(tuple_value.eth_saddr, eth->h_dest, ETH_ALEN);

		tuple_value.creation_cpu = bpf_get_smp_processor_id();
		if (bpf_map_update_elem(&XBI_TUPLES_MAP_NAME, &tuple_key
		, &tuple_value, BPF_ANY))
			statsp->lru_fail_map_tuples++;
		else
			statsp->lru_alloc_map_tuples++;

		// Check non-SYN|RST packets for TCP options, track in stats any
		// SACK option which would indicate somehow the flow was still
		// active yet there was no state present until now.   Likely
		// misdirection, perhaps a director change but could be due to
		// misrouting.
		if (tcph->syn) {
			statsp->lru_alloc_syns++;
			goto NEXT_PROG_OR_PASS;
		} else
			statsp->lru_alloc_nonsyns++;

#define SACK_MIN_LEN (1 + 1 + 4 + 4)	// opt#, opt len, left & right sequence
#define	SACK_LEN_WORDS ((SACK_MIN_LEN + 3) / 4)  // # 4-byte SACK option words

		// No options, insufficient options words, or they go beyond
		// the current buffer if there was a 1-block SACK option within.
		curroptp = ((unsigned char *)&tcph[1]);
		if (tcph->th_off <= sizeof(struct tcphdr) / 4
		|| SACK_LEN_WORDS > tcph->th_off - (sizeof(struct tcphdr) /4)
		|| curroptp + (SACK_LEN_WORDS << 2) - 1 > data_end)
			goto NEXT_PROG_OR_PASS;

		// Most common SACK TCP options sequences to check for:
		//     NOP, NOP, SACK [, TS]
		//     NOP, NOP, TS, NOP, NOP, SACK
		// Also checking for non-NOP variants of the above.
		// Weird single-byte NOPs defeats the below, not worth checking
		// for those cases even for the slow path of fastpath code.
		if ((curroptp[0] == TCPOPT_NOP && curroptp[1] == TCPOPT_NOP
		&& curroptp[2] == TCPOPT_SACK)
		|| curroptp[0] == TCPOPT_SACK) {
			statsp->suspect_misflows_sack++;
			goto NEXT_PROG_OR_PASS;
		}

		// sack_offset = 0;
		if (curroptp[0] == TCPOPT_TIMESTAMP)
			sack_offset = curroptp[1];
		else if (curroptp[0] == TCPOPT_NOP && curroptp[1] == TCPOPT_NOP
		&& curroptp[2] == TCPOPT_TIMESTAMP)
			sack_offset = curroptp[3] + 2;
		else
			goto NEXT_PROG_OR_PASS;

		// Move on to next likely spot for SACK option, check that
		// its still within packet limit AND covered by the TCP
		// header options length sufficiently to hold at least a
		// minimum-length SACK block.
		curroptp = ((unsigned char *)&tcph[1]) + sack_offset;
		if (curroptp + SACK_MIN_LEN - 1 > data_end
		|| sack_offset + SACK_MIN_LEN
		> (tcph->th_off << 2) - sizeof(struct tcphdr))
			goto NEXT_PROG_OR_PASS;

		if ((curroptp[0] == TCPOPT_NOP && curroptp[1] == TCPOPT_NOP
		&& curroptp[2] == TCPOPT_SACK)
		|| curroptp[0] == TCPOPT_SACK)
			statsp->suspect_misflows_sack++;

		goto NEXT_PROG_OR_PASS;
	} else if (tuple_valuep->rst_sent_out) {
		uint	index;
		__u32	info_be32;
		tc_outbound_rates_t * outboundp;
		__u16	plen_u16;
		__u64	time_diff_ns;
		unsigned char tmp_eth[ETH_ALEN];
		__u16	tmp_u16;
		__u32	tmp_u32;

		time_diff_ns = curr_time_ns - tuple_valuep->last_activetime;
		if (tcph->syn && time_diff_ns > paramsp->inactive_nsecs) {
			// Flow old, prior RSTs may be from earlier instance.
			// So if this is a SYN, its worth trying to re-resolve
			// the flow.  One potential low-liklihood risk here:
			// This can bypass the drop probablity path for "new"
			// flows by throwing attack ACKs, pausing, then
			// getting the associated SYN in at high loads without
			// the drop test.  But since this is not a "new" flow,
			// the state exists, can justify the cheap effort to
			// make it productive.
			goto restart_resolution;
		}

		// OK to send back RST, but not to another RST!
		if (tcph->rst) {
			statsp->in_rsts_disc_flow++;
			ret_status.action = XDP_DROP;
			goto XDPCAP_RETURN_WITH_STATUS;
		}

		// SYN packets may be a rapid reuse, or delayed retransmit.
		// Pass up to ipvs for its verification.  Successful resolve
		// resets the RST counter in "tc" outbound.
		if (tcph->syn)
			goto NEXT_PROG_OR_PASS;

		// Discard incoming packet if over flow quota or is "too soon"
		// since prior active time.   Allow for a reasonable delay to
		// restart sending of RSTs.
		if (time_diff_ns > 10*(__u64)1000000000) {
			// Been a while, reset counter to resend a few out.
			tuple_valuep->rst_sent_out = 1;
		} else if (tuple_valuep->rst_sent_out > 5
		|| time_diff_ns < 10*1000*1000) {
			// Too many or too fast, so drop outgoing RST for flow.
			statsp->out_rsts_disc_flow++;
                        if (!paramsp->monitor_only && paramsp->limit_rates) {
				ret_status.action = XDP_DROP;
				goto XDPCAP_RETURN_WITH_STATUS;
			}
		}

		// Check per-CPU RSTs rate limiting.
		index = 0;
		outboundp = bpf_map_lookup_elem(&XBI_OUTBOUND_RATES_MAP_NAME
		, &index);

		// This is not possible, but must keep the BPF verifier
		// happy.   Just "drop" this packet, if in active mode.
		if (!outboundp) {
                        statsp->out_rsts_disc_rate++;
                        if (!paramsp->monitor_only && paramsp->limit_rates) {
				ret_status.action = XDP_DROP;
				goto XDPCAP_RETURN_WITH_STATUS;
			}
			goto NEXT_PROG_OR_PASS;
		}

		// Update outbound epoch or otherwise confirm sufficient rate
		// exists to send back a RST.
                if (curr_time_ns > outboundp->end_time_ns) {
                        outboundp->start_time_ns = curr_time_ns;
                        outboundp->end_time_ns = curr_time_ns
                        + paramsp->out_rsts_epoch_ns;
                        outboundp->rsts_sent = 0;
                } else if (outboundp->rsts_sent > paramsp->out_rsts) {
                        statsp->out_rsts_disc_rate++;
                        if (!paramsp->monitor_only && paramsp->limit_rates) {
				ret_status.action = XDP_DROP;
				goto XDPCAP_RETURN_WITH_STATUS;
			}
                }
		outboundp->rsts_sent++;

		// Sending a reset, transform current packet into a RST.
		// Doing an active send, update last active time.
		tuple_valuep->last_activetime = curr_time_ns;
		tuple_valuep->rst_sent_out++;
		statsp->out_rsts_sent_xdp++;

		// Flip ethernet src/dst fields.
		memcpy(tmp_eth, eth->h_dest, ETH_ALEN);

		// TOCONSIDER: Allow parameter configuraton of a specific
		// router MAC to use, though this "flip" should typically
		// suffice.
		memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tmp_eth, ETH_ALEN);

		// Flip src/dst IP addresses, no checksum adjust needed.
		tmp_u32 = iph->daddr;
		iph->daddr = iph->saddr;
		iph->saddr = tmp_u32;

		// Flip local/remote TCP ports, no checksum adjust needed.
		tmp_u16 = tcph->th_dport;
		tcph->th_dport = tcph->th_sport;
		tcph->th_sport = tmp_u16;

		//
		// It can be useful to record on generated RSTs the incoming
		// fields that may provide a clue such as flags, ttl, and
		// length.  For minimum length incoming packets the fields
		// will be appended to the packet buffer area but NOT added
		// into the packet length, so they will appear in the "padding"
		// area which allows visibility from xdpcap and local systems.
		// For incoming packets larger than minimum, the start of the
		// incoming TCP data or options will be overwritten instead
		// and checksum adjusted.   Sending data on a RST is legal but
		// unusual, so this may need to be turned into a truncation of
		// the RST by default (enable for internal debugging).  In the
		// case where the packet length is NOT minimum but ALSO is
		// less than 4 bytes beyond minimum then the info fields are
		// also saved in the "padding" area.
		//
		// TOCONSIDER: Truncate longer packets to minimum RST length
		// which will require full packet checksum instead of the
		// incremental adjustments.  Info fields would remain beyond
		// IP packet length to reside in the padding.
		//

		// 4 bytes of potentially useful info from incoming packet.
		plen_u16 = bpf_ntohs(iph->tot_len);
		info_be32= bpf_htonl((((tcph->th_flags << 8) + iph->ttl) << 16)
		+ plen_u16);

		// Will save info bytes in packet proper, checksum adjusted.
		if ((char *)&tcph[1] + 4 <= data_end
		&& (plen_u16 >= sizeof(struct iphdr) + sizeof(struct tcphdr)
		+ 4)) {
			// Data or options to hold 4 bytes of incoming info
			// immediately following the base headers.
			csum_replace4(&tcph->th_sum, *(__u32 *)&tcph[1]
			, info_be32);
			*(__u32 *)&tcph[1] = info_be32;

		// Packet length does not cover all/any of the 4 bytes following
		// the TCP header.   TCP packet data is 0 -> 3 bytes.  So follow
		// the TCP data, if any, with the 4 info bytes if there is the
		// space for it.   These bytes will not be included in the
		// checksum and it is possible, such as for a 3-byte TCP packet,
		// that the info bytes can not be inserted for those RSTs.
		} else if ((char *)&tcph[1] + (0x03 & plen_u16) + 4 <= data_end
		&& plen_u16 < sizeof(struct iphdr) + sizeof(struct tcphdr)
		+ 4) {
			*(__u32 *)((char *)&tcph[1] + (0x03 & plen_u16))
			= info_be32;
		}

		// Zap TCP ACK flag so only need sequence field, set RST flag.
		// Zap any other flags such as congestion.  Adjust the th_off,
		// x2, and flags which follow th_ack field.  Adjust checksum.
		// Since this is a RST, remove any incoming TCP options so
		// none are reflected back to the client erroneously.
		// Note that data/header offset and reserved flags bits
		// follow ACK and precede the flags byte in the packet.
		//
		// Note: Incoming TCP options would be returned as some amount
		// of "data" beyond minimum header length.   This is ok, based
		// on TCP spec and at least invalid RST options are not being
		// "reflected".
		csum_replace2(&tcph->th_sum, ((__u16 *)&tcph->th_ack)[2]
		, bpf_htons((((sizeof(struct tcphdr) / 4) << 4) << 8)
		+ TH_RST));
		tcph->th_off = sizeof(struct tcphdr) / 4;
		tcph->th_x2 = 0;
		tcph->th_flags = TH_RST;

		// If TTL is not at least 64, adjust checksum and match the TTL.
		if (iph->ttl < 64) {
			// TTL field is followed by protocol (TCP), so pass
			// network-order 16-bits for old and new values.
			csum_replace2(&iph->check, *(__u16 *)&iph->ttl
			, htons((64 << 8) + IPPROTO_TCP));
			iph->ttl = 64;
		}

		// Ack -> Seq so RST is in expected range, but since we are
		// not setting the ACK bit must zap ack and adjust checksum.
		csum_replace4(&tcph->th_sum, tcph->th_seq, 0);
		tcph->th_seq = tcph->th_ack;
		tcph->th_ack = 0;

		// TODO: Check for over-sized RST because original packet
		// had data.  This is legitimate, but may look odd to some or
		// may be discarded by some firewall. XDP truncate/adjust and
		// checksum entire TCP header with pseudo-header using
		// bpf_csum_diff() using only the "to" size.

		// Done, exit with XDP_TX to send the packet back out.
		ret_status.action = XDP_TX;
		goto XDPCAP_RETURN_WITH_STATUS;
	} else if (!tuple_valuep->resolved) {
		/* Entry exists but not yet resolved, note this occurs. */
		statsp->resolution_pending++;

		/* If too many packets over too much time, drop it. */

		/* TODO: Parameterize(?) how to clean up entry?  Reuse on time
		 * since "last drop" (add new field)?   User space background
		 * sweep these up so can eventually reuse tuple?  Better may
		 * be a bpf kprobe in ipvs hook points to mark (free?) state
		 * for reuse or even to delete it.  Also an outbound LRU
		 * entry can be used to prevent RSTs (time-base would still
		 * prevent all RSTs from being suppressed).
		 */
		tuple_valuep->pkts_outbound++;

		// Too many (flow start) or "possible" mid-flow ACKs/requests
		// that have not received an ipvs response in too long (5ms)
		// will get dropped.  An exception is if its been SO long that
		// its worth trying to restart the resolution process.  In the
		// later case we risk another 5ms of possible attack packets,
		// but reclaim a now-possibly-good client tuple.
		if (tuple_valuep->pkts_outbound > 10) {
			// Bump a stat for delayed resolution, unlikely to be
			// a stream of ACKs.  Mark flow so only do this once
			// per new or reused LRU state.
			if (!tuple_valuep->resolve_delay) {
				tuple_valuep->resolve_delay = 1;
				statsp->lru_res_delayed++;
			}

			last_activetime_ns = curr_time_ns
			- tuple_valuep->last_activetime;
			if (last_activetime_ns > paramsp->inactive_nsecs)
				goto restart_resolution;
			else if (last_activetime_ns > 5000000) {
				// TODO: Consider rate-limited RSTs for clients.
				statsp->resolution_drops++;
				if (paramsp->monitor_only)
					goto NEXT_PROG_OR_PASS;
				ret_status.action = XDP_DROP;
				goto XDPCAP_RETURN_WITH_STATUS;
			}
		}
		goto NEXT_PROG_OR_PASS;
	} else if (tuple_valuep->resolve_delay == 1) {
		// Resolved but marked delayed, RPS race that can be cleared up.
		tuple_valuep->resolve_delay = 0;
		statsp->lru_res_delayed_fixed++;
	}

	/*
	 * Determine if "too old", ipvs state needs to synchronize with
	 * ipvs for sure.  Just need to get the latest resolution, if any.
	 */
	last_activetime_ns = tuple_valuep->last_activetime;
	if (curr_time_ns - last_activetime_ns > paramsp->inactive_nsecs) {
restart_resolution: ;
		/* A "miss" should only be for first (or fast rexmit) SYN */
		if (tcph->syn)
			statsp->lru_reuse_syns++;
		else if (tcph->rst) {
			// Do not recreate an LRU for resets(!), just pass.
			// Note that prior packets may still be in flight to
			// the TC exit processing, so a "miss" may be recorded
			// in stats.
			statsp->lru_deletion_RST++;
			bpf_map_delete_elem(&XBI_TUPLES_MAP_NAME, &tuple_key);
			statsp->lru_alloc_map_tuples--;
			goto NEXT_PROG_OR_PASS;
		} else
			statsp->lru_reuse_nonsyns++;

		/* Reinitialize flow state as if new. */
		cpunum = tuple_valuep->creation_cpu;
		if (!tuple_valuep->resolved) {
			// Some potential resolution on re-resolve info
			delayval = tuple_valuep->resolve_delay;
		} else
			delayval = 0;
		memset((void *)tuple_valuep, 0, sizeof(tuple_value));

		// Initialize timestamps and other preserved settings.
		tuple_valuep->last_activetime = curr_time_ns;
		tuple_valuep->prev_ipvstime = curr_time_ns;
		tuple_valuep->last_ipvstime = curr_time_ns;

		tuple_valuep->creation_cpu = cpunum;
		if (delayval) {
			// Diagnostic to denote delay
			tuple_valuep->resolve_delay = 2;
		}

		statsp->inactivity_timeout++;
		goto NEXT_PROG_OR_PASS;
	}

	// Checks done, record last time of packet processing.
	tuple_valuep->last_activetime = curr_time_ns;

	/*
	 * A RST on active flow, delete flow and PASS up to kernel.   Do not
	 * do delete for FIN, for the case of a client done sending requests
	 * BUT has initiated a long-running download which will result in lots
	 * of ACKs that would benefit from the xdp_bypass_ipvs here.   Note for
	 * this later case that the regular "sampling" of an ACK PASSed into the
	 * kernel should serve to maintain the ipvs connection state, even if
	 * "inactive" as in the case of the FIN while other direction active.
	 */
	if (tcph->rst) {
		statsp->lru_deletion_RST++;

		// TODO: Convince ourselves this is NOT a new DDOS issue.
		// Note that prior packets may still be in flight to
		// the TC exit processing, so a "miss" may be recorded
		// in stats.
		// TODO: To alleviate the above, keep track of next-expected
		// sequence number and only on match do this, just like Linux
		// itself.
		// TODO: Further, possible to track ACK numbers to possibly
		// create a correct return ACK to elicit a proper RST?
		// Or at least record data/rates for tuples.
		bpf_map_delete_elem(&XBI_TUPLES_MAP_NAME, &tuple_key);
		statsp->lru_alloc_map_tuples--;
		goto NEXT_PROG_OR_PASS;
	}

	// FIN needs to be seen by ipvs to transition to "inactive", but only
	// a few FINs to deal with (unlikely) losses are needed by ipvs.  Bypass
	// the rest, if any, subject to regular ipvs "keep alive" handling.
	if (tcph->fin && tuple_valuep->fin_seen < 5) {
		tuple_valuep->fin_seen++;
		goto NEXT_PROG_OR_PASS;
	}

	// Possible flow reuse, reset pkts_outbound to keep ipvs state happy
	// with follow-up ACK(s).  Could just be an unneeded retransmit, then
	// the cost is a few more initial packets going up to ipvs which
	// should usually be fine.
	if (tcph->syn)
		tuple_valuep->pkts_outbound = 0;

	/* TODO: ipvs behavior, check TTL==1.  XDP_PASS to ipvs to handle? */
	/* For higher TTLs, is it worth decrementing and checksum adjust? */

	/*
	 * Use configured sample time rate to determine if a packet should be
	 * sent to iptables + ipvs.  But if we have not sent a certain number
	 * up to ipvs on this flow, sample as well to be sure gets in the
	 * ESTABLISHED state.  Also, if we are in the accelerated FIN seen
	 * state then go 4x the usual sample rate.
	 *
	 * Note: This will likely lead to reordering of the XDP_PASS'ed packet
	 * but for ACKs we expect this to be almost totally immaterial and thats
	 * the most common case.   If for data, then this reordering may be a
	 * bit more regular than naturally occurs in the Internet anyway but
	 * TCP has some robustness against this.   It would be nice to use just
	 * ACKs or short data packets instead of reordering full-sized data
	 * frames but there is no guarantee that a given flow uploading data
	 * would ever generate enough of these.
	 */
	last_ipvstime_ns = curr_time_ns - tuple_valuep->last_ipvstime;
	if (tuple_valuep->pkts_outbound < 10
	|| (tuple_valuep->fin_seen && last_ipvstime_ns
	> (((__u64)3ull * 1000000000ull + paramsp->sample_nsecs) >> 2))
	|| last_ipvstime_ns > paramsp->sample_nsecs) {
		tuple_valuep->prev_ipvstime = tuple_valuep->last_ipvstime;
		tuple_valuep->last_ipvstime = curr_time_ns;
		goto NEXT_PROG_OR_PASS;
	}

	// Count another packet received to fastpath on flow.
	tuple_valuep->pkts_bypass++;

	/* Special "monitor mode" does everything except send the packet. */
	if (paramsp->monitor_only)
		goto NEXT_PROG_OR_PASS;

	// Non-monitor mode, bump global packet bypass ipvs counter.
        statsp->total_bypassed_pkts++;

	/* Going to send packet, insert VLAN header if configured. */
	if (paramsp->vlan_hdr_tag != -1) {
		if (bpf_xdp_adjust_head(ctx
		, (int)(sizeof(struct ethhdr) - sizeof(struct vlan_ethhdr)))) {
			/* Unable to allocate VLAN header space. */
			statsp->adjust_head_errors++;
			ret_status.action = XDP_DROP;
			goto XDPCAP_RETURN_WITH_STATUS;
		}

		/* Reset header pointers, above call assumed to move data. */
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		/*
		 * Ethernet + VLAN to init at new start of buffer, current eth
		 * is slightly higher in memory.
		 */
		veth = data;
		eth = data
		+ (int)(sizeof(struct vlan_ethhdr) - sizeof(struct ethhdr));

		if (&veth[1] > data_end || &eth[1] > data_end) {
			/* This "can't happen", but keeps verifier happy. */
			statsp->adjust_head_errors++;
			ret_status.action = XDP_DROP;
			goto XDPCAP_RETURN_WITH_STATUS;
		}

		veth->h_vlan_proto = htons(ETH_P_8021Q);
		veth->h_vlan_TCI = bpf_htons((__u16)paramsp->vlan_hdr_tag);

		if (veth->h_vlan_encapsulated_proto != htons(ETH_P_IP)) {
			/* Header adjust did not line up properly. */
			statsp->adjust_head_errors++;
			ret_status.action = XDP_DROP;
			goto XDPCAP_RETURN_WITH_STATUS;
		}

		/* Final VLAN handling to send, based on redirect mode. */
		if (paramsp->use_xdp_tx) {
			/* TX out same interface, 1st memcpy must overlap. */
			memcpy(veth->h_source, eth->h_dest, ETH_ALEN);
			memcpy(veth->h_dest, tuple_valuep->eth_daddr, ETH_ALEN);
			ret_status.action = XDP_TX;
			goto XDPCAP_RETURN_WITH_STATUS;
		} else {
			/* Redirect path needs the proper source MAC saved. */
			memcpy(veth->h_source, tuple_valuep->eth_saddr
			, ETH_ALEN);
			memcpy(veth->h_dest, tuple_valuep->eth_daddr, ETH_ALEN);
			bpf_redirect(tuple_valuep->ifindex, 0);
			ret_status.action = XDP_REDIRECT;
			goto XDPCAP_RETURN_WITH_STATUS;
		}
	}

	/* Non-VLAN header send. */
	if (paramsp->use_xdp_tx) {
		/* TX packet out destination interface with proper MAC addrs. */
		memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
		memcpy(eth->h_dest, tuple_valuep->eth_daddr, ETH_ALEN);
		ret_status.action = XDP_TX;
	} else {
		/* Redirect out to specified interface, eth_saddr pre-cached. */
		/* TODO: Solve or pull out this "slow path" code. */
		memcpy(eth->h_dest, tuple_valuep->eth_daddr, ETH_ALEN);
		memcpy(eth->h_source, tuple_valuep->eth_saddr, ETH_ALEN);
		bpf_redirect(tuple_valuep->ifindex, 0);
		ret_status.action = XDP_REDIRECT;
	}

XDPCAP_RETURN_WITH_STATUS:;
	if (paramsp->mode_progarray) {
		XDPCAP_RETURN(ctx, ret_status);
	}
	return ret_status.action;

NEXT_PROG_OR_PASS:;
	if (paramsp->mode_progarray) {
		CALL_NEXT();	// Passes "ctx" to programs @ XDP_PROG_ARRAY_IDX
		ret_status.action = XDP_PASS;
		ret_status.code = XDP_CODE_MU;
		ret_status.meta = 0x00;
		XDPCAP_RETURN(ctx, ret_status);
	}
	return XDP_PASS;
}

/* Redirect option requires an XDP bpf_prog loaded on the other outbound NIC. */
SEC("xdp")
int XBI_DUMMY_PROG_NAME(struct xdp_md *ctx)
{
	return XDP_PASS;
}

// Code-build version for loader sanity checks.
char xdp_bypass_ipvs_headers_sha256sum[]
	SEC("XDP_BYPASS_IPVS_COMMON_H_SHA256")
	= XDP_BYPASS_IPVS_COMMON_H_SHA256;

char _license[] SEC("license") = "APL";
