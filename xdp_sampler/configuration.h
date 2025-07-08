#ifndef _xdp_sampler_configuration_h
#define _xdp_sampler_configuration_h
#include <limits.h>

#define SRV_TYPE_FILE "/oc/local/config/srvtype"

// Stuff that comes in from the host and optargs
struct sampler_cfg {
	// populated by configuration_populate_ec_info
	char hostname[HOST_NAME_MAX];
	char pop[256];
	char srvtype[256];

	// optarg stuff
	bool debug;
	char port[16];
	bool statsd_enable;
	char statsd_host[254]; // https://devblogs.microsoft.com/oldnewthing/?p=7873
	char statsd_port[16]; // https://tools.ietf.org/html/rfc6335#section-5.1
};

struct sampler_cfg *configuration_new();
void configuration_free(struct sampler_cfg *cfg);
#endif // _xdp_sampler_configuration_h
