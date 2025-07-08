#ifndef __LIBECBPF_XDP_STATS_H
#define __LIBECBPF_XDP_STATS_H

#include <stdint.h>

/*
 * Statistics Definitions.  This mirrors enum xdp_action
 * with the addition of an XDP_INVALID_RETURN
 */
enum stats_array_idxs {
	STAT_XDP_ABORTED = 0,
	STAT_XDP_DROP,
	STAT_XDP_PASS,
	STAT_XDP_TX,
	STAT_XDP_REDIRECT,
	STAT_XDP_INVALID_ACTION,
	STAT_XDP_MAX
};

/*
 * Statistics collected upon exit
 */
struct xdp_stats {
	uint64_t action_count[STAT_XDP_MAX];
};

#endif // __LIBECBPF_XDP_STATS_H
