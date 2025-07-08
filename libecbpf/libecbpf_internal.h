#ifndef __LIBECBPF_LIBECBPF_INTERNAL_H
#define __LIBECBPF_LIBECBPF_INTERNAL_H

#include "libecbpf.h"

#define STATSD_MAX_MSG 1024 // Simple limit for statsd messages

void ecbpf_log_print(enum libbpf_print_level level, const char *format, ...);

#define ecbpf_debug(fmt, ...) ecbpf_log_print(LIBBPF_DEBUG, "libecbpf: DEBUG: " fmt, ##__VA_ARGS__)
#define ecbpf_info(fmt, ...) ecbpf_log_print(LIBBPF_INFO, "libecbpf: INFO: " fmt, ##__VA_ARGS__)
#define ecbpf_warn(fmt, ...) ecbpf_log_print(LIBBPF_WARN, "libecbpf: WARN: " fmt, ##__VA_ARGS__)

#endif // __LIBECBPF_LIBECBPF_INTERNAL_H
