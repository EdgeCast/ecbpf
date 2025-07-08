#define ECBPF_KERN

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include "xdp_printk.h"
#include "libecbpf_kern.h"

SEC("xdp")
int XDP_PRINTK_PROG_NAME(struct xdp_md *ctx)
{
	xdpcap_retval_t retval = {XDP_PASS, XDP_CODE_MU, 0x00};

	bpf_printk("Hello from slot %i\n", XDP_PROG_ARRAY_IDX);

	CALL_NEXT();

	XDPCAP_RETURN(ctx, retval);	// fall through
}

char _license[] SEC("license") = "XDP";
