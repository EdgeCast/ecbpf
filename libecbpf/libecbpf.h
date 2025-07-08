#ifndef __LIBECBPF_LIBECBPF_H
#define __LIBECBPF_LIBECBPF_H

#include <stdbool.h>
#include <stdint.h>
#include <gelf.h>
#include "libecbpf_config.h"
#include "xdp_stats.h"
#include "bpf.h" // from libbpf submodule
#include "libbpf.h" // from libbpf submodule
#define LIBECBPF // for maps

#ifndef LIBECBPF_API // Makefile sets visibility to hidden by default
#define LIBECBPF_API __attribute__((visibility("default")))
#endif

struct ecbpf_ctx;
extern const char *xdp_stat_names[STAT_XDP_MAX];

// Logging

// We attempts to build on the logging used by libbpf, so we use their
// function def and levels
LIBBPF_API libbpf_print_fn_t libecbpf_set_print(libbpf_print_fn_t fn);

// BPF sysfs helpers
LIBECBPF_API int ecbpf_mount_bpf_fs();
LIBECBPF_API int ecbpf_check_bpf_fs();
LIBECBPF_API int ecbpf_get_map_fd(char *path);

// Logging
#define LIBECBPF_STATSD_HOST "127.0.0.1"
#define LIBECBPF_STATSD_PORT "8125"
#define LIBECBPF_STATSD_MAX_BACKOFF 600
LIBECBPF_API libbpf_print_fn_t ecbpf_log_set_print(libbpf_print_fn_t fn);
LIBECBPF_API void ecbpf_log_set_debug();
LIBECBPF_API int ecbpf_log_statsd_counter(char *host, char *port, char *metric, uint64_t count);
LIBECBPF_API int ecbpf_log_statsd_gauge(char *host, char *port, char *metric, uint64_t value);

// ECBPF Context Methods
LIBECBPF_API struct ecbpf_ctx *ecbpf_ctx__new();
LIBECBPF_API void ecbpf_ctx__free(struct ecbpf_ctx *ctx);

LIBECBPF_API int ecbpf_ctx__set_bpf_obj(struct ecbpf_ctx *ctx, struct bpf_object *obj);
LIBECBPF_API int ecbpf_ctx__set_xdp_mode(struct ecbpf_ctx *ctx, unsigned int mode);
LIBECBPF_API int ecbpf_ctx__set_xdp_mode_generic(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf_ctx__set_xdp_mode_driver(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf_ctx__set_interface(struct ecbpf_ctx *ctx, char *if_name);
LIBECBPF_API int ecbpf_ctx__set_namespace(struct ecbpf_ctx *ctx, char *namespace);
LIBECBPF_API char *ecbpf_ctx__namespace(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf_ctx__set_pinned_map(struct ecbpf_ctx *ctx, char *map_name);
LIBECBPF_API int ecbpf_ctx__set_force_load(struct ecbpf_ctx *ctx, bool on);
LIBECBPF_API int ecbpf_ctx__set_subprogram_test(struct ecbpf_ctx *ctx, bool on);
LIBECBPF_API int ecbpf_ctx__set_subprogram_update(struct ecbpf_ctx *ctx, bool on);
LIBECBPF_API int ecbpf_ctx__get_root_prog_fd(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf_ctx__get_subprogram_fd(struct ecbpf_ctx *ctx);

// Root program handling
LIBECBPF_API int ecbpf__load_root_program(struct ecbpf_ctx *ctx, char *filename, char *root_prog_name);
LIBECBPF_API int ecbpf__attach_root_program(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf__detach_root_program(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf__check_root_program(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf__clear_statistics(struct ecbpf_ctx *ctx);

// Map handling methods
LIBECBPF_API int ecbpf__pin_map(struct ecbpf_ctx *ctx, char *map_name);
LIBECBPF_API int ecbpf__unpin_map(struct ecbpf_ctx *ctx, char *map);
LIBECBPF_API int ecbpf__get_map_fd(struct ecbpf_ctx *ctx, char *map_name);

// Subprogram handling methods
LIBECBPF_API int ecbpf__subprogram_open(struct ecbpf_ctx *ctx, char *filename);
LIBECBPF_API int ecbpf__subprogram_close(struct ecbpf_ctx *ctx);
LIBECBPF_API int ecbpf__subprogram_reuse_map(struct ecbpf_ctx *ctx, char *map_name);
LIBECBPF_API int ecbpf__subprogram_detach(struct ecbpf_ctx *ctx, int slot);
LIBECBPF_API int ecbpf__subprogram_attach(struct ecbpf_ctx *ctx, char *prog_name, int slot);
LIBECBPF_API int ecbpf__subprogram_slot_prog_id(struct ecbpf_ctx *ctx, int slot);
LIBECBPF_API int ecbpf__subprogram_slot_prog_fd(struct ecbpf_ctx *ctx, int slot);
LIBECBPF_API int ecbpf__subprogram_slot_bpf_prog_info(struct ecbpf_ctx *ctx, int slot, struct bpf_prog_info *prog_info, uint32_t *prog_info_len);
LIBECBPF_API int ecbpf__subprogram_slot_name(struct ecbpf_ctx *ctx, int slot, char *dst, size_t len);
LIBECBPF_API int ecbpf__subprogram_slot_load_time(struct ecbpf_ctx *ctx, int slot, time_t *dst);
LIBECBPF_API int ecbpf__subprogram_slot_statistics(struct ecbpf_ctx *ctx, int slot, struct xdp_stats *);
LIBECBPF_API int ecbpf__subprogram_slot_statistics_clear(struct ecbpf_ctx *ctx, int slot);

// Elf API methods
LIBECBPF_API Elf *ecbpf_elf_open_filename(const char *filename, int *fd);
LIBECBPF_API Elf_Scn *ecbpf_elf_find_section(Elf *e, Elf64_Word type, const char *name);
LIBECBPF_API int ecbpf_elf_mutate_symbols(Elf *e, void *ctx, int (*mutator)(GElf_Sym *sym, Elf_Data *data, int ndx, char* name, void *ctx));
LIBECBPF_API int ecbpf_elf_set_maps_notype(Elf *e);
LIBECBPF_API int ecbpf_elf_write_close(Elf *e, int fd);

#endif // __LIBECBPF_LIBECBPF_H
