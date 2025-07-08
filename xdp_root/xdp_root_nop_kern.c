/*
 * Root XDP nop program for use when root is unloaded
 */
#include <linux/types.h>
#include <bpf_helpers.h>
#include <linux/bpf.h>
#include "rootmaps.h" // Section name definition

SEC("xdp")
int ROOT_PROG_NOP_NAME(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "APL";
