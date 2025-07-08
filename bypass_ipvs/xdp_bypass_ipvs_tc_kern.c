/*
 * ipvs bypass ("ACK accelerator" or just "fastpath") consists of a user
 * space map/code loader and parameter/control settings ; the XDP eBPF inbound
 * component ; and the TC eBPF outbound component.
 *
 * The main description of how the XDP and TC portions work is in the "xdp_kern"
 * source file along with the XDP component.   The TC code is contained here.
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
#include <linux/pkt_cls.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#define	XDP_BYPASS_IPVS_KERNEL_EBPF
#define	XDP_BYPASS_IPVS_IPROUTE2_MAPS
#include "xdp_bypass_ipvs_common.h"

/*
 * Traffic control filter bound to an interface egress to inspect all outgoing
 * packets marked by ipvs for forwarding to a real server.  There should be
 * a minimum of return/inbound traffic due to LVS DSR and that most of the
 * traffic is presumably being bypassed by the above XDP portion.
 */
SEC("classifier")
int XBI_TC_PROG_NAME (struct __sk_buff *skb)
{
	__be16	frag_off;
	int	fwm;
	__be16	h_proto;
	__u8 *	hwaddr;
	int	ifindex;
	int	index;
	tc_interface_info_t * interfacep;
	int	internet;
	int	iphdrlen;
	__u8	protocol;
	xdp_bypass_params_t * paramsp;
	xdp_global_stats_t * statsp;
	__u8	tcpflags;
	xdp_bypass_dest_intf_t * tuple_valuep;
	xdp_bypass_4tuple_t tuple_key;
	long *	valuep;

	/* Get pointers to critical parameters and stats that MUST be there. */
	index = 0;
	paramsp = bpf_map_lookup_elem(&XBI_PARAMS_MAP_NAME, &index);
	statsp = bpf_map_lookup_elem(&XBI_STATS_MAP_NAME, &index);

	if (!paramsp || !statsp) {
		/*
		 * Give up, not much to do here on this impossible(?) case.
		 * Slam the zeroth element with a -1 to indicate we are not
		 * running/processing any packet flows.
		 */
		fwm = 0;
		valuep = bpf_map_lookup_elem(&XBI_FWM_MAP_NAME, &fwm);
		if (valuep)
			*valuep = -1;
		return TC_ACT_OK;
	}

	statsp->total_pkts_tc_tx++;

	// Need interface flags to know whether working on Internet side
	// with outgoing packet back to client or inside interface for packets
	// heading outbound to server.  This "tc" program is hooked at "egress"
	// so they are "outbound" packets heading towards the driver TX.
	//
	// TOCONSIDER: Can eliminate the interface map lookup by breaking
	// the RST-related Internet code into its own "tc" program.   The
	// bpf_redirect() processing, which isn't currently used due to
	// performance, would also be pulled out.  User space would associate
	// the proper "tc" program with the Internet or Internal interfaces.
	// Not done this way initially due to the shared interface used in
	// transition, duplication of code, that this isn't the main code
	// path when fastpath is enabled so the extra lookup isn't that costly,
	// and to await completion of multi-NIC bonds which would be the correct
	// time to do this.
	ifindex = skb->ifindex;
	interfacep = bpf_map_lookup_elem(&XBI_INTERFACES_MAP_NAME, &ifindex);
	if (!interfacep) {
		// Some weird configuration error here?
		statsp->unknown_interface++;
		return TC_ACT_OK;
	}

	internet = interfacep->if_flags & TC_INTF_F_INTERNET;

	// Only process inside packets to servers that are marked.
	if (!internet && !skb->mark)
		return TC_ACT_OK;

	/* Validate ethernet header present, load up protocol type. */
	if (skb->len < sizeof(struct ethhdr))
		return TC_ACT_OK;
	h_proto = load_half(skb, offsetof(struct ethhdr, h_proto));

	/* Only handle IPv4 packets to demo this, note local byte order. */
	if (h_proto != ETH_P_IP)
		return TC_ACT_OK;

	/* Validate IP header and contains TCP header. */
	if (skb->len < sizeof(struct ethhdr) + sizeof(struct iphdr))
		return TC_ACT_OK;

#define IPHDR_OFF (sizeof(struct ethhdr))
#define TCPHDR_OFF (sizeof(struct ethhdr) + iphdrlen)

	protocol = load_byte(skb, IPHDR_OFF + offsetof(struct iphdr, protocol));
	frag_off = load_half(skb, IPHDR_OFF + offsetof(struct iphdr, frag_off));

	if (protocol != IPPROTO_TCP || (~IP_DF & frag_off) != 0)
		return TC_ACT_OK;

	/* 4-bit IP header word len is in the zeroth byte with IP version. */
	iphdrlen = (0x0f & load_byte(skb, IPHDR_OFF)) << 2;

	if (skb->len < TCPHDR_OFF + sizeof(struct tcphdr))
		return TC_ACT_OK;

	// Set up to look up tuple of outgoing packet in the main inbound LRU
	// fastpath map.  The info for the interface that the packet is heading
	// out was looked up earlier to determine which fields are moved into
	// the tuple key.
	memset((void *)&tuple_key, 0, sizeof(tuple_key));
	if (internet) {
		// Source addr/port are the local addr/port and vice-versa.
		bpf_skb_load_bytes(skb, IPHDR_OFF + offsetof(struct iphdr
		, saddr), &tuple_key.laddr.v4, sizeof(tuple_key.laddr.v4));
		bpf_skb_load_bytes(skb, IPHDR_OFF + offsetof(struct iphdr
		, daddr), &tuple_key.raddr.v4, sizeof(tuple_key.raddr.v4));
		bpf_skb_load_bytes(skb, TCPHDR_OFF + offsetof(struct tcphdr
		, source), &tuple_key.lport, sizeof(tuple_key.lport));
		bpf_skb_load_bytes(skb, TCPHDR_OFF + offsetof(struct tcphdr
		, dest), &tuple_key.rport, sizeof(tuple_key.rport));
	} else {
		// Source addr/port are the remote addr/port and vice-versa.
		bpf_skb_load_bytes(skb, IPHDR_OFF + offsetof(struct iphdr
		, saddr), &tuple_key.raddr.v4, sizeof(tuple_key.raddr.v4));
		bpf_skb_load_bytes(skb, IPHDR_OFF + offsetof(struct iphdr
		, daddr), &tuple_key.laddr.v4, sizeof(tuple_key.laddr.v4));
		bpf_skb_load_bytes(skb, TCPHDR_OFF + offsetof(struct tcphdr
		, source), &tuple_key.rport, sizeof(tuple_key.rport));
		bpf_skb_load_bytes(skb, TCPHDR_OFF + offsetof(struct tcphdr
		, dest), &tuple_key.lport, sizeof(tuple_key.lport));
	}
	tuple_key.family = (h_proto == ETH_P_IP) ? AF_INET : AF_INET6;

	/* TCP Flags byte immediately precedes "window" field bytes. */
	tcpflags = load_byte(skb
	, TCPHDR_OFF + offsetof(struct tcphdr, window) - 1);

#define	TCP_FIN	0x01
#define	TCP_SYN	0x02
#define	TCP_RST	0x04

	// RSTs require special handling to rate control and terminate inbound
	// fastpath state if destined back to internet clients (or attackers).
	// TOCONSIDER: Rate-limit other "bad flow" packets, such as ICMPs.
	if (tcpflags & TCP_RST) {
		__u64	curr_time_ns;
		int	index;
		tc_outbound_rates_t * outboundp;
		int	ret_status;

		// Due to current dual-direction of drivers under bond VLAN
		// interfaces, exit if this is an interface explicitly heading
		// towards the server or is an iptable/ipvs marked RST which
		// indicates this is an internet-origin packet being forwarded
		// to the server (despite the interface claiming internet).
		if (!internet || skb->mark)
			return TC_ACT_OK;

		// Look up flow, must mark it as being RST whether the RST
		// gets emitted below through the rate limiting code or not.
		// Possible race on cross-CPU rst_sent_out++, should not
		// matter more than a couple RSTs more per flow.
		tuple_valuep = bpf_map_lookup_elem(&XBI_TUPLES_MAP_NAME
		, &tuple_key);
		if (tuple_valuep && !tuple_valuep->rst_sent_out)
			tuple_valuep->rst_sent_out++;

		// Lookup current per-CPU RSTs rate for epoch (such as 100ms)
		// and apply limit to current packet, updating the rate stats.
		// In this per-CPU map, there is just a single entry.
		index = 0;
		outboundp = bpf_map_lookup_elem(&XBI_OUTBOUND_RATES_MAP_NAME
		, &index);
		if (!outboundp) {
			// This really can not happen unless the map is not
			// large enough for all CPUs in use.
			statsp->out_rsts_sent_tc++;
			return TC_ACT_OK;
		}

		curr_time_ns = bpf_ktime_get_ns();
		if (tuple_valuep && !tuple_valuep->rst_sent_out) {
			__u64	prev_ipvstime_ns;

			prev_ipvstime_ns = curr_time_ns
			- tuple_valuep->prev_ipvstime;

			// First RST is unexpected if its been at least a little
			// while (100ms) since last signalling ipvs with a
			// packet and yet less than the sample time (+1 sec
			// to provide margin) used for ipvs that assures state
			// is kept alive.   If the tuple is in "FIN seen" state,
			// the check is done at 4x the rate (+(3+1) sec base).
			if (prev_ipvstime_ns > 100*1000*1000) {
				if (tuple_valuep->fin_seen) {
					if (prev_ipvstime_ns
					< (((__u64)(3ull+1ull) * 1000000000ull)
					+ paramsp->sample_nsecs) >> 2)
						statsp->unexpected_ipvs_rsts++;
				} else {
					if (prev_ipvstime_ns
					< paramsp->sample_nsecs + 1000000000ull)
						statsp->unexpected_ipvs_rsts++;
				}
			}
		}

		if (curr_time_ns > outboundp->end_time_ns) {
			outboundp->start_time_ns = curr_time_ns;
			outboundp->end_time_ns = curr_time_ns
			+ paramsp->out_rsts_epoch_ns;
			outboundp->rsts_sent = 0;
		} else if (outboundp->rsts_sent > paramsp->out_rsts) {
			statsp->out_rsts_disc_rate++;
			// Do not actually discard the packet if in monitor
			// mode or limiting of rates not enabled.
			if (!paramsp->monitor_only && paramsp->limit_rates)
				return TC_ACT_SHOT;
		}

		// RST flows permitted, see if individual flow quota met.
		if (!tuple_valuep) {
			// Unknown flow, possible non-ipvs flow.
			outboundp->rsts_sent++;
			statsp->out_rsts_unknown++;
			statsp->out_rsts_sent_tc++;
			return TC_ACT_OK;
		}

		// If flow has met quota or is too-fast RST, discard here
		// for XDP to finish any still-needed RSTs.
		if (tuple_valuep->rst_sent_out >= 2) {
			statsp->out_rsts_disc_flow++;
			if (!paramsp->monitor_only && paramsp->limit_rates)
				return TC_ACT_SHOT;
		}

		// Possible race in tuple increment below, worst case should be
		// an extra set of RSTs may get sent for a flow that hits
		// this.  Better than always-present memory atomicity/barriers.
		outboundp->rsts_sent++;
		tuple_valuep->rst_sent_out++;
		statsp->out_rsts_sent_tc++;
		return TC_ACT_OK;

	}

	// No further processing of Internet-bound packets, remaining code
	// only does fastpath resolution and stats for fastpath flows.
	if (internet)
		return 0;

	/*
	 * # of flows that triggered ipvs bypass, using SYNs.  Approximate due
	 * to potential SYN retransmission.
	 */
	if (tcpflags & TCP_SYN) {
		fwm = skb->mark;
		valuep = bpf_map_lookup_elem(&XBI_FWM_MAP_NAME, &fwm);
		if (valuep)
			__sync_fetch_and_add(valuep, 1);
		else {
			/* Firewall mark too large, put in bucket 0. */
			fwm = 0;
			valuep = bpf_map_lookup_elem(&XBI_FWM_MAP_NAME, &fwm);
			if (valuep)
				__sync_fetch_and_add(valuep, 1);
		}
	}

	tuple_valuep = bpf_map_lookup_elem(&XBI_TUPLES_MAP_NAME, &tuple_key);
	if (!tuple_valuep) {
		// Note stats only if not an excluded address in src (remote
		// address) field which would mean this is a local-originated
		// packet, such as a health check.  This should be a rare event
		// for normally-accelerated packets.
		__u32	* addr_valuep;
                addr_valuep = bpf_map_lookup_elem(&XBI_V4LADDRS_MAP_NAME
                , &tuple_key.raddr.v4);
                if (!addr_valuep) {
			// Record missing state failure: SYN or non-SYN.
			// Note: These can occur as a result of a "race" between
			// an XDP side RST deleting the state before this TC
			// path gets to finish, such as in RPS scheduling.
			if (tcpflags & TCP_SYN)
				statsp->lru_miss_out_syn++;
			else
				statsp->lru_miss_out_nonsyn++;
		} else {
			// Should never get any hits here, due to no FWM.
			// TOCONSIDER: Remove the v4addrs_local_map lookup?
			statsp->ipv4_outbound_local_marked++;
		}
		return 0;
	}

	/* Tuple exists/resolved, just bump outbound counter. */
	if (tuple_valuep->resolved) {
		unsigned char temp_daddr[ETH_ALEN];

		tuple_valuep->pkts_outbound++;

		// See if MAC address has changed by ipvs, if so then update it.
		// Note: This became a new requirement due to use of the maglev
		// hash along with ipvs sysctls "expire_nodest_conn" and the
		// "sloppy_tcp" which together enable a quick MAC change to a
		// new server from which a quick TCP RST is desired.
		//
		// Note: Cache-line spoilage avoided here by reading for the
		// comparison and, only if there is a change, THEN spoil the
		// cache line by a write that impacts the XDP fastpath portion.
		bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest)
		, temp_daddr, ETH_ALEN);

		// No eBPF bcmp/memcmp so do XOR compare for all equal/zero.
#define XADDR(i) (temp_daddr[i] ^ tuple_valuep->eth_daddr[i])
		if (XADDR(0) | XADDR(1) | XADDR(2)
		|   XADDR(3) | XADDR(4) | XADDR(5))
			memcpy(tuple_valuep->eth_daddr, temp_daddr, ETH_ALEN);
#undef XADDR
	} else {
		/* Only do this if in redirect mode. */
		if (!paramsp->use_xdp_tx) {
			/*
			 * Need interface source MAC for redirect case.   Could
			 * make inbound path do a per-packet map lookup of the
			 * tuple's ifindex in the MAC map but is more
			 * CPU-efficient at the cost of extra memory to just
			 * record it now.
			 */
			hwaddr = interfacep->hwaddr;
			memcpy(&tuple_valuep->eth_saddr[0], hwaddr, ETH_ALEN);
			tuple_valuep->ifindex = ifindex;
		}

		/* Resolve complete entry with outgoing dest addr. */
		bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest)
		, &tuple_valuep->eth_daddr[0], ETH_ALEN);
		tuple_valuep->pkts_outbound = 1;

		// Diagnostic tracking of if/when delayed resolution occurs.
		if (tuple_valuep->resolve_delay == 1)
			statsp->lru_res_delayed_fixed++;
		else if (tuple_valuep->resolve_delay == 2)
			statsp->lru_res_reuse_fix++;

		tuple_valuep->resolved = 1;
		tuple_valuep->resolve_delay = 0;
	}

	// Flow (re)resolved, make sure RST processing is off.
	tuple_valuep->rst_sent_out = 0;
	return TC_ACT_OK;
}
char _license[] SEC("license") = "APL";
