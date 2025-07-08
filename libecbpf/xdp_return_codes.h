#ifndef _XDP_RETURN_CODES
#define _XDP_RETURN_CODES 1

typedef struct {
	int action;
	uint32_t code;
	uint64_t meta;
} xdpcap_retval_t;

#define XDP_CODE_MU 0 // https://en.wikipedia.org/wiki/Mu_(negative)

// General Errors
#define XDP_CODE_VERIFIER_ERR			0x1  // Stuff that should never trigger 
#define XDP_CODE_ETH_LEN_ERR            0x2  // Sanity check for ethernet header length failed
#define XDP_CODE_IP_LEN_ERR             0x3  // Sanity check for ip header length failed
#define XDP_CODE_IP6_LEN_ERR            0x4  // Sanity check for ip6 header length failed
#define XDP_CODE_NON_IP                 0x5  // non-ip packet passed to the kernel
#define XDP_CODE_MAP_ERR                0x6  // problem with a map lookup
#define XDP_CODE_TCP_LEN_ERR			0x7  // TCP header length problem
#define XDP_CODE_UDP_LEN_ERR			0x8  // TCP header length problem
#define XDP_CODE_ICMP_LEN_ERR			0x9  // TCP header length problem
#define XDP_CODE_ADJ_HEAD_ERR			0x10 // Memory allocation error
#define XDP_CODE_ADJ_TAIL_ERR			0x11 // Memory allocation error
#define XDP_CODE_IP_UNSUPP_PROTO		0x12 // Non TCP/UDP/ICMP IP packet
#define XDP_CODE_IP6_UNSUPP_PROTO		0x13 // Non TCP/UDP/ICMP IPv6 packet

// XDP Filter Codes
#define XDP_CODE_FILTER_IP_DROP         0x100 // Source filtering dropped IP packet
#define XDP_CODE_FILTER_IP6_DROP        0x101 // Source filtering dropped IPv6 packet
#define XDP_CODE_FILTER_IP_FRAG_DROP    0x102 // Dropped a fragment
#define XDP_CODE_FILTER_TOT_LEN_DROP    0x103 // Dropped a fragment with weird length
#define XDP_CODE_FILTER_IP_OPT_DROP     0x104 // Dropped due to ip options set
#define XDP_CODE_FILTER_IP_EVIL_DROP    0x105 // Dropped due to evil bit set
#define XDP_CODE_FILTER_PTB             0x106 // PTB sent
#define XDP_CODE_FILTER_PTB_VERIFY_ERR  0x107 // Internal error creating the PTB response

// XDP Firewall Codes
#define XDP_CODE_FW_DROP				0x200 // Rules matched, packet dropped.  Metadata should be matches.
#define XDP_CODE_FW_NO_QINQ				0x201 // No Q in Q VLAN support

#endif // _XDP_RETURN_CODES
