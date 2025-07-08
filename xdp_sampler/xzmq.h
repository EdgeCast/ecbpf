#ifndef _xdp_sampler_xzmq_h
#define _xdp_sampler_xzmq_h

#define PUSH_PULL_URL "inproc://samples"

extern void *zmq_context;
struct xzmq_ctx;
struct xzmq_ctx *xzmq_ctx_new(char *port);
void xzmq_ctx_free(struct xzmq_ctx *ctx);

void xzmq_start(struct xzmq_ctx *ctx);
void xzmq_stop(struct xzmq_ctx *ctx);


#endif // _xdp_sampler_xzmq_h
