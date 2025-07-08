#define _XOPEN_SOURCE 700	// for nftw
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ftw.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netdb.h>
#include <time.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <sys/mount.h>

#include "libecbpf.h"
#include "libecbpf_internal.h"
#include "rootmaps.h"
#include "xdp_stats.h"

// Internal helper methods
static int unpin_root_program_maps(struct ecbpf_ctx *ctx);
static int pin_root_program_maps(struct ecbpf_ctx *ctx);
static int map_path(struct ecbpf_ctx *ctx, char *path, int len, const char *map_name);
static int unpin_root_program_maps(struct ecbpf_ctx *ctx);
static int unpin_unlink(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);
static int validate_subprogram_slot(int slot);
static int get_prog_array_fd(struct ecbpf_ctx *ctx);
static int resolve_filename(char *filename, char *buffer, size_t len);
static int ecbpf_log_statsd(char *host, char *port, char *metric);


/**
 * @file libecbpf.c
 * @author  John Hickey
 * @brief Main routines for libecbpf.
 */

/**
 * @struct pinned_map
 * @brief Linked list of pinned maps used by the ecbpf context
 *
 */
struct pinned_map {
	char *map;
	struct pinned_map *next;
};

/**
 * @struct ecbpf_ctx
 * @brief Context for working with BPF programs.
 *
 * All these values have functions of the form ecbpf_ctx__ to modify them.
 * The struct itself is not exported.
 */
struct ecbpf_ctx {
	char *if_name;
	char *namespace;
	int if_index;
	unsigned int xdp_flags;
	struct bpf_object *bpf_obj;
	struct pinned_map *pinned_maps;
	bool force;
	bool subprogram_update;
	bool subprogram_test;
	int root_prog_fd;
	int sub_prog_fd;
};


const char *sys_fs_bpf = "/sys/fs/bpf";

/*
 * Statistic Names
 */
const char *xdp_stat_names[] = {
	[STAT_XDP_ABORTED] = "XDP_ABORTED",
	[STAT_XDP_DROP] = "XDP_DROP",
	[STAT_XDP_PASS] = "XDP_PASS",
	[STAT_XDP_TX] = "XDP_TX",
	[STAT_XDP_REDIRECT] = "XDP_REDIRECT",
	[STAT_XDP_INVALID_ACTION] = "XDP_INVALID_ACTION"
};

/** @defgroup ecbpf_log Log functions for libecbpf
 *  @{
 */

/**
 * @brief Internal variable referencing function to use for printing out log messages for libecbpf
 */
static enum libbpf_print_level __ecbpf_log_level = LIBBPF_INFO;

/**
 * @brief Internal default printer for log messages.
 *
 * Also supplied to libbpf when log level is set to debug.
 *
 */
static int __ecbpf_default_pr(enum libbpf_print_level level, const char *format, va_list args)
{
    /*
     * In enum libbpf_print_level: warn = 1, info =2, debug =3
     */
    if (level > __ecbpf_log_level)
        return 0;

    return vfprintf(stderr, format, args);
}

/**
 * @brief Internal variable referencing function to use for printing out log messages for libecbpf
 */
static libbpf_print_fn_t __libecbpf_pr = __ecbpf_default_pr;

/**
 * @brief Set print function for logging.
 * @param fn Log print function
 *
 * This print function is fed to both libbpf and libecbpf.
 */
libbpf_print_fn_t ecbpf_log_set_print(libbpf_print_fn_t fn)
{
	libbpf_set_print(fn);
    libbpf_print_fn_t old_print_fn = __libecbpf_pr;
    __libecbpf_pr = fn;

    return old_print_fn;
}


/**
 * @brief Internal log printing function.  Mirrors libbpf.
 */
__attribute__((format(printf, 2, 3)))
void ecbpf_log_print(enum libbpf_print_level level, const char *format, ...)
{
    va_list args;

    if (!__libecbpf_pr)
        return;

    va_start(args, format);
    __libecbpf_pr(level, format, args);
    va_end(args);
}

/**
 * @brief Set libecbpf and libbpf logging to debug.
 */
void ecbpf_log_set_debug()
{
	__ecbpf_log_level = LIBBPF_DEBUG;
	ecbpf_log_set_print(&__ecbpf_default_pr);
}


/**
 * @brief Internal submit to statsd function
 */
static int ecbpf_log_statsd(char *host, char *port, char *msg) {
	int fd, err, len;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	err = getaddrinfo(host, port, &hints, &res);

	if (err != 0) {
		if (err == EAI_SYSTEM)
			ecbpf_warn("ecbpf_log_statsd: getaddrinfo failed: %m\n");
		else
			ecbpf_warn("ecbpf_log_statsd: getaddrinfo failed: %s\n", gai_strerror(err));

		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(fd);
	}

	freeaddrinfo(res);

	if (rp == NULL) {
		ecbpf_warn("ecbpf_log_statsd: Could not connect to %s:%s\n", host, port);
		return -1;
	}

	len = write(fd, msg, strlen(msg));
	close(fd);

	if (len != strlen(msg)) {
		ecbpf_warn("ecbpf_log_statsd: failed socket write\n");
		return -1;
	}

	return 0;
}

/**
 * @brief Report a statsd counter
 * @param host Hostname or IP
 * @param port Port or Service Name
 * @param metric Metric for statsd
 *
 * Statsd counters need to be reported every second.  The hard-coded
 * statsd namespace is xdp.
 *
 * @return 0 if the successful, otherwise negative.
 */
int ecbpf_log_statsd_counter(char *host, char *port, char *metric, uint64_t count) {
	char msg[STATSD_MAX_MSG];

	snprintf(msg, STATSD_MAX_MSG, "xdp.%s:%lu|c", metric, count);

	return ecbpf_log_statsd(host, port, msg);
}

/**
 * @brief Report a statsd gauge
 * @param host Hostname or IP
 * @param port Port or Service Name
 * @param value Metric for statsd gauge
 *
 * @return 0 if the successful, otherwise negative.
 */
int ecbpf_log_statsd_gauge(char *host, char *port, char *metric, uint64_t value) {
	char msg[STATSD_MAX_MSG];

	snprintf(msg, STATSD_MAX_MSG, "xdp.%s:%lu|g", metric, value);

	return ecbpf_log_statsd(host, port, msg);
}
/** @} */ // end of ecbpf_log

/** @defgroup bpffs_helper BPF Filesystem Helpers
 *  @{
 */

/**
 * @brief Mount the bpf filesystem.
 *
 * Older linux versions don't automatically mount /sys/fs/bpf.
 *
 * @return Result from mount syscall, which is 0 on success, negative on error.
 */
int ecbpf_mount_bpf_fs()
{
	int err;

	ecbpf_info("Mounting BPF filesystem\n");

	err =
	    mount("bpf", sys_fs_bpf, "bpf",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, "");

	if (err < 0) {
		ecbpf_warn("Failed to mount bpf filesystem on %s: %s\n",
			sys_fs_bpf, strerror(errno));
	}

	return err;
}

/**
 * @brief Make sure the bpf filesystem is mounted.
 *
 * Check that /sys/fs/bpf exists and has the correct magic.
 *
 * @return 0 if the filesystem is mounted proprely, otherwise negative.
 */
int ecbpf_check_bpf_fs()
{
	struct statfs fs;

	if (statfs(sys_fs_bpf, &fs) == -1) {
		ecbpf_info("Failed to stat bpf fs mount point %s: %s",
			sys_fs_bpf, strerror(errno));
		return -ENOENT;
	}

	if (fs.f_type != BPF_FS_MAGIC) {
		ecbpf_info("BPF filesystem not mounted on %s\n",
			sys_fs_bpf);
		return -ENOENT;
	}

	return 0;
}

/**
 * @brief Make sure the memlock rlimit is set to load bpf progs
 *
 * @return 0 if the rlimit is ok, otherwise negative.
 */
int ecbpf_set_rlimit()
{
	int err;
	struct rlimit rlimit_unlimited = {RLIM_INFINITY, RLIM_INFINITY};

	err = setrlimit(RLIMIT_MEMLOCK, &rlimit_unlimited);

	if (err) {
		ecbpf_warn("Failed to setrlimit: %s", strerror(errno));
	}

	return err;
}

/**
 * @brief Helper for getting a pinned map fd.
 *
 * @return Map fd or a negative error on failure.
 */
int ecbpf_get_map_fd(char *path)
{
	char fd_path[PATH_MAX];
	char link[PATH_MAX];
	int ret;
	int fd;

	fd = bpf_obj_get(path);

	if (fd < 0) {
		return fd;
	}
	snprintf(fd_path, PATH_MAX, "/proc/self/fd/%i", fd);

	// make sure it is a map
	memset(link, 0, sizeof(link)); // readlink doesn't add a null at the end
	ret = readlink(fd_path, link, sizeof(link));
	if (ret < 0) {
		ecbpf_warn("Failed to get fd info for path %s: %m\n",
			fd_path);
		return -ENOENT;
	}

	if (ret == sizeof(link)) {
		ecbpf_warn("Truncated path returned by readlink for %s\n",
			fd_path);
		return -ENAMETOOLONG;
	}

	if (strstr(link, "bpf-map"))
		return fd;

	ecbpf_warn("Expected bpf-map as substring of path %s. Pinned object not a map?\n",
		link);
	return -EINVAL;
}

/** @} */ // end of bpffs_helper


/** @defgroup ctx ECBPF Context Methods
 *  @{
 */

/**
 * @brief Allocate an empty struct ecbpf_ctx
 *
 * XDP mode defaults to SKB mode.
 *
 * @return An empty ecbpf_ctx or NULL on failure
 */
struct ecbpf_ctx *ecbpf_ctx__new() {
	struct ecbpf_ctx *ctx;

	ctx = calloc(1, sizeof(struct ecbpf_ctx));

	if (ctx == NULL) {
		ecbpf_warn("Failed to allocate memory for ecbpf_ctx: %m\n");
		return NULL;
	}

	ctx->if_index = -1;
	ctx->root_prog_fd = -1;
	ctx->sub_prog_fd = -1;
	ctx->pinned_maps = NULL;

	// We default to driver mode for prod.  We also set XDP_FLAGS_UPDATE_IF_NOEXIST
	// so we don't force load.
	ctx->xdp_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
	ctx->force = false;
	ctx->subprogram_update = false;
	ctx->subprogram_test = false;

	return ctx;
}

/**
 * @brief Free a struct ecbpf_ctx.
 * @param ctx ecbpf_ctx.
 */
void ecbpf_ctx__free(struct ecbpf_ctx *ctx) {
	struct pinned_map *cur, *next;

	if (ctx->namespace) {
		free(ctx->namespace);
	}

	if (ctx->if_name) {
		free(ctx->if_name);
	}

	if (ctx->bpf_obj) {
		bpf_object__close(ctx->bpf_obj);
	}


	cur = ctx->pinned_maps;

	while (cur) {
		next = cur->next;
		if (cur->map)
			free(cur->map);
		free(cur);
		cur = next;
	}

	free(ctx);
}

/**
 * @brief Manually set bpf object
 * @param ctx ecpbf_ctx
 * @param obj struct bpf_object
 *
 * Manually plumb in an existing BPF object.  This is to allow
 * the xdp ack fast path loader to use the subprogram array without
 * significantly changing the code.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_bpf_obj(struct ecbpf_ctx *ctx, struct bpf_object *obj) {

	if (ctx->bpf_obj) {
		ecbpf_warn("Context already has bpf object set and can not be reset\n");
		return -EINVAL;
	}
	ctx->bpf_obj = obj;

	return 0;
}

/**
 * @brief Set the XDP flags
 * @param ctx ecbpf_ctx
 * @param mode XDP_FLAGS_SKB_MODE or XDP_FLAGS_DRV_MODE
 *
 * Set the mode for when attaching/detaching the root program
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_xdp_mode(struct ecbpf_ctx *ctx, unsigned int mode)
{
    if (mode & ~XDP_FLAGS_MASK) {
		ecbpf_warn("Invalid xdp mode flags\n");
		return -EINVAL;
	}

	ctx->xdp_flags = mode;

	// Keep track of force, since we can pass in XDP_FLAGS_UPDATE_IF_NOEXIST
	ctx->force = mode & XDP_FLAGS_UPDATE_IF_NOEXIST;

	return 0;
}

/**
 * @brief Set XDP flags to force program loading
 * @param ctx ecbpf_ctx
 * @param on Set true to turn on force, false to clear
 *
 * XDP_FLAGS_UPDATE_IF_NOEXIST is named a little unintuitively.  If this
 * flag is set and a program is attached, we will get back EBUSY.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_force_load(struct ecbpf_ctx *ctx, bool on)
{
	ctx->force = on;

    if (ctx->force) {
		ctx->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
	} else {
		ctx->xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	}

	return 0;
}

/**
 * @brief When attaching a subprogram update instead of redoing
 * @param ctx ecbpf_ctx
 * @param on Set true to turn on updating, false to clear
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_subprogram_update(struct ecbpf_ctx *ctx, bool on)
{
	ctx->subprogram_update = on;

	return 0;
}

/**
 * @brief When attaching a subprogram, don't put fd in root map
 * @param ctx ecbpf_ctx
 * @param on Set true to turn on updating, false to clear
 *
 * This is so that we can get a subprogram plumbed in, but
 * make sure that it is not put in the root map and it handed empty
 * maps for prog array, etc.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_subprogram_test(struct ecbpf_ctx *ctx, bool on)
{
	ctx->subprogram_test = on;

	return 0;
}

/**
 * @brief Set XDP flags to generic mode
 * @param ctx ecbpf_ctx
 *
 * @return 0 on success, negative on failure,
 */
int ecbpf_ctx__set_xdp_mode_generic(struct ecbpf_ctx *ctx) {

	ctx->xdp_flags &= ~XDP_FLAGS_DRV_MODE;
	ctx->xdp_flags |= XDP_FLAGS_SKB_MODE;

	return 0;
}

/**
 * @brief Set XDP flags to driver mode
 * @param ctx ecbpf_ctx
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_xdp_mode_driver(struct ecbpf_ctx *ctx) {

	ctx->xdp_flags &= ~XDP_FLAGS_SKB_MODE;
	ctx->xdp_flags |= XDP_FLAGS_DRV_MODE;

	return 0;
}

/**
 * @brief Assocaite ecbpf_ctx with a particular interface
 * @param ctx ecbpf_ctx
 * @param if_name Name of the network interface
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_interface(struct ecbpf_ctx *ctx, char *if_name)
{
	if ((ctx->if_index = if_nametoindex(if_name)) == 0) {
		ecbpf_warn("Failed to get index for interface '%s': %m\n",
			if_name);
		return -ENODEV;
	}

	if (ctx->if_name)
		free(ctx->if_name);

	ctx->if_name = strdup(if_name);

	return 0;
}

/**
 * @brief Set the namespace.
 * @param ctx ecbpf_ctx
 * @param namespace namespace
 *
 * Namespace is the directory in bpf fs where maps will be pinned.
 * It defaults to the network interface name.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_namespace(struct ecbpf_ctx *ctx, char *namespace)
{
	if (ctx->namespace)
		free(ctx->namespace);

	ctx->namespace = strdup(namespace);

	return 0;
}

/**
 * @brief Pin a map upon attach.
 * @param ctx ecbpf_ctx.
 * @param map_name map name to be pinned.
 *
 * Adds a map name to be pinned when the program is loaded.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf_ctx__set_pinned_map(struct ecbpf_ctx *ctx, char *map_name)
{

	int i;
	struct pinned_map *map;

	map = calloc(1, sizeof(struct pinned_map));

	if (!map) {
		ecbpf_warn("Unable to allocated pinned map struct\n");
		return -ENOMEM;
	}

	map->map = strdup(map_name);
	map->next = ctx->pinned_maps;
	ctx->pinned_maps = map;

	return 0;
}

/**
 * @brief Get the namespace.
 * @param ctx ecbpf_ctx
 *
 * Namespace is the directory in bpf fs where maps will be pinned.
 * It defaults to the network interface name.
 *
 * @return namespace or NULL if not set.
 */
char *ecbpf_ctx__namespace(struct ecbpf_ctx *ctx)
{
	if (ctx->namespace)
		return ctx->namespace;

	if (ctx->if_name)
		return ctx->if_name;

	return NULL;
}

/**
 * @brief Get program fd for the root array.
 * @param ctx ecbpf_ctx
 *
 * @return program fd, negative if not set.
 */
int ecbpf_ctx__get_root_prog_fd(struct ecbpf_ctx *ctx)
{
	return ctx->root_prog_fd;
}

/**
 * @brief Get program fd for the last attached subprogram.
 * @param ctx ecbpf_ctx
 *
 * @return program fd, negative if not set.
 */
int ecbpf_ctx__get_subprogram_fd(struct ecbpf_ctx *ctx)
{
	return ctx->sub_prog_fd;
}

/** @} */ // end of bpffs_helper

/** @defgroup root ECBPF Root program array methods
 *  @{
 */

/**
 * @brief Clear/initialize statistics map
 * @param ctx ecbpf_ctx
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__clear_statistics(struct ecbpf_ctx *ctx) {
	int err;
	int fd;
	int np;
	struct xdp_stats *stats;

	np = libbpf_num_possible_cpus(); // XDP_STATS_MAP_NAME is a per cpu array for concurrency reasons

	err = ecbpf__check_root_program(ctx);

	if (err) {
		ecbpf_warn("Root ecbpf program not attached.\n");
		return err;
	}

	fd = ecbpf__get_map_fd(ctx, xstr(XDP_STATS_MAP_NAME));

	if (fd < 0) {
		// Note that we assume the map is pinned already
		ecbpf_warn("Unable to get XDP_STATS_MAP_NAME file descriptor.\n");
		return err;
	}

	// Zeroed counts
	stats = calloc((size_t) np, sizeof(struct xdp_stats));

	if (stats == NULL) {
		ecbpf_warn("Failed to allocate xdp_stats array.\n");
		return -ENOMEM;
	}

	for (int slot = 0; slot < SUBPROGRAM_MAX; slot++) {
		err = bpf_map_update_elem(fd, &slot, stats, BPF_ANY);

		if (err) {
			ecbpf_warn("Failed to update progarray map\n");
			return err;
		}
	}

	return 0;
}

/**
 * @brief Internal helper for root program maps
 * @param ctx ecbpf_ctx
 *
 * We can't just use bpf_object__pin_maps at the moment.  This is because of:
 * commit d859900c4c56dc4f0f8894c92a01dad86917453e
 * Author: Daniel Borkmann <daniel@iogearbox.net>
 * Date:   Tue Apr 9 23:20:13 2019 +0200
 *
 * bpf, libbpf: support global data/bss/rodata sections
 *
 * This commit creates some internal maps that end in ".data", etc.  The BPF filesystem
 * does not support filenames with currently (see bpf_lookup in kernel/bpf/inode.c).
 * @return 0 on success, negative on failure.
 */
static int pin_root_program_maps(struct ecbpf_ctx *ctx)
{
	char path[PATH_MAX];
	int err;

	err = map_path(ctx, path, sizeof(path), NULL);
	if (err) {
		ecbpf_warn("Failed to get namespace path\n");
		return err;
	}
		
	mkdir(path, 0755);	// TODO: error check here...

	// Map for programs
	err = ecbpf__pin_map(ctx, xstr(ROOT_MAP_NAME));
	if (err) {
		return err;
	}

	// Map for exit hook programs
	err = ecbpf__pin_map(ctx, xstr(XDPCAP_MAP_NAME));
	if (err) {
		return err;
	}

	// Map for statistics
	err = ecbpf__pin_map(ctx, xstr(XDP_STATS_MAP_NAME));
	if (err) {
		return err;
	}

	// Map for samples
	err = ecbpf__pin_map(ctx, xstr(XDP_SAMPLER_MAP_NAME));
	if (err) {
		return err;
	}

	return 0;
}

/**
 * @brief Internal helper
 *
 * Cleans up a namespace by unpinning all maps.  Used when
 * detaching the root program.
 * @return 0 on success, negative on failure.
 */
int unpin_root_program_maps(struct ecbpf_ctx *ctx)
{
	char path[PATH_MAX];
	struct stat buf;
	int err;

	err = map_path(ctx, path, sizeof(path), NULL);
	if (err) {
		ecbpf_warn("unpin_root_program_maps: Failed to get map path\n");
		return err;
	}

	// Make sure the path exists (for ctx->force)
	err = stat(path, &buf);
	if (err) {
		ecbpf_info("unpin_root_program_maps: Can't stat map path %s: %m\n", path);
		return -errno;
	}

	// unpinning is really simple.  Since objects are reference counted, having them present in bpffs creates
	// a permanent reference.  Simply unlinking the reference will reap the map if no programs using it are
	// loaded.
	err = nftw(path, unpin_unlink, 23, FTW_DEPTH | FTW_PHYS);	// flags mean handle directory after files in director and no symlinks
	if (err) {
		ecbpf_warn("unpin_root_program_maps: Unpinning failed: %m\n");
		return -errno;
	}

	return 0;
}

/**
 * @brief Internal helper to search for program files in /usr/share...
 *
 * Check if filename exists.  If it does not, see if it exists in the
 * BPF_PROGRAM_PATH directory.
 *
 * @return 0 on success, negative on failure.
 */
static int resolve_filename(char *filename, char *buffer, size_t len) {
	char path[PATH_MAX];
	char *src;
	int err;

	err = access(filename, F_OK);
	if (err) {
		snprintf(path, sizeof(path), BPF_PROGRAM_PATH "/%s", filename);
		err = access(path, F_OK);
		if (err) {
			ecbpf_warn("Filename '%s' was not found.\n", filename);
			ecbpf_warn("Check for '%s' in " BPF_PROGRAM_PATH " failed.\n", filename);
			return -errno;
		}
		src = path;
	} else {
		src = filename;
	}

	strncpy(buffer, src, len - 1);
	buffer[len-1] = '\0';

	return 0;
}

/**
 * @brief Internal helper for getting the current FD of the attached root program
 *
 * @return FD of root program or -ENOENT if there isn't on.  On failure -EOPNOTSUPP.
 */
int get_current_root_prog_fd(struct ecbpf_ctx *ctx, struct bpf_prog_info *prog_info, u_int32_t *prog_info_len) {
	int err, curr_prog_fd;
	uint32_t curr_prog_id = 0;

	// Check to see if a program is already attached
	err = bpf_xdp_query_id(ctx->if_index, ctx->xdp_flags, &curr_prog_id);
	if (err) {
		ecbpf_warn("Failed to query if or if not a XDP program is currently attachted to interface %s: %s\n\n",
			ctx->if_name, strerror(-err));
		return -EOPNOTSUPP;
	}

	if (!curr_prog_id) {
		return -ENOENT;
	}

	curr_prog_fd = bpf_prog_get_fd_by_id(curr_prog_id);

	if (curr_prog_fd < 0) {
		ecbpf_warn("Failed to get FD of currently loaded program on interface %s: %s\n\n",
			ctx->if_name, strerror(-curr_prog_fd));
		return -EOPNOTSUPP;
	}

	// Populate prog_info in case we want to compare names.
	err = bpf_prog_get_info_by_fd(curr_prog_fd, prog_info, prog_info_len);
	if (err) {
			ecbpf_warn("Error getting running root program info.\n\n");
			return -EOPNOTSUPP;
	}

	return curr_prog_fd;
}

/**
 * @brief Load the root program array
 * @param ctx ecbpf_ctx
 * @param filename Elf object file containing the root array program
 * @param name of the root program section to load
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__load_root_program(struct ecbpf_ctx *ctx, char *filename, char *root_prog_name) {
	struct bpf_program *root_program;
	struct bpf_object *obj;
	char resolved_filename[PATH_MAX];
	int err;
	int prog_fd;

	// make sure rlimits are set
	err = ecbpf_set_rlimit();
	if (err)
		return err;

	// make sure bpf_fs is present
	err = ecbpf_check_bpf_fs();
	if (err) {
		// attempt to mount
		err = ecbpf_mount_bpf_fs();
		if (err) {
			return err;
		}
	}

	// Resolve the filename
	err = resolve_filename(filename, resolved_filename, sizeof(resolved_filename));
	if (err) {
		return err;
	}

	// Open the object file
	obj = bpf_object__open_file(resolved_filename, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		ecbpf_warn("Failed to open bpf object: %s\n", strerror(err));
		return err;
	}


	// Load the object
	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		ecbpf_warn("Failed to load bpf object: %s\n", strerror(err));
		return err;
	}

	// Lookup the root program
	root_program =
	    bpf_object__find_program_by_name(obj, root_prog_name);

	if (root_program == NULL) {
		bpf_object__close(obj);
		ecbpf_warn("Failed to find section '%s' in bpf program.\n",
				root_prog_name);
		return -ENOENT;
	}

	// Lookup the root program fd
	prog_fd = bpf_program__fd(root_program);
	if (prog_fd < 0) {
		bpf_object__close(obj);
		ecbpf_warn("Failed to get root program fd.\n");
		return -ENOENT;
	}

	// update context
	ctx->bpf_obj = obj;
	ctx->root_prog_fd = prog_fd;

	return 0;
}

/**
 * @brief Attach the root program array
 * @param ctx ecbpf_ctx
 * @param filename Elf object file containing the root array program
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__attach_root_program(struct ecbpf_ctx *ctx)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
	int err, prog_fd;
	struct bpf_prog_info prog_info = {};
	uint32_t prog_info_len = sizeof(prog_info);
	int curr_prog_fd;
	unsigned int flags = ctx->xdp_flags;

	prog_fd = ecbpf_ctx__get_root_prog_fd(ctx);

	// Do a replace if there is already something on the interface
	curr_prog_fd = get_current_root_prog_fd(ctx, &prog_info, &prog_info_len);
	if (curr_prog_fd >= 0) {
		ecbpf_info("Performing XDP program replace.\n");

		if (strcmp(prog_info.name, xstr(ROOT_PROG_NOP_NAME))) {
			ecbpf_warn("Unexpected XDP program '%s' attached to interface '%s'.\n",
					   prog_info.name,
					   ctx->if_name);
			return -EBUSY;
		}

		attach_opts.old_prog_fd = curr_prog_fd;
		flags &= XDP_FLAGS_REPLACE;
	}

	// Do the attach
	err = bpf_xdp_attach(ctx->if_index, prog_fd, flags, &attach_opts);
	if (err) {
		ecbpf_warn("Failed to attach program to interface %s: %s\n\n",
			ctx->if_name, strerror(-err));
		return err;
	}

	if (ctx->force) {
		ecbpf_info("Root program being attaced with force mode.  "
			   "All existing maps in namespace will be removed!\n");
		unpin_root_program_maps(ctx);
	}

	err = pin_root_program_maps(ctx);

	if (err) {
		ecbpf_warn("Failed to pin root program maps\n");
		return err;
	}

	err = ecbpf__clear_statistics(ctx);

	if (err) {
		ecbpf_warn("Failed to clear root program statistics\n");
		return err;
	}

	return 0;
}

/**
 * @brief Detach the root array.
 * @param ctx ecbpf_ctx
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__detach_root_program(struct ecbpf_ctx *ctx)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
	struct bpf_prog_info prog_info = {};
	uint32_t prog_info_len = sizeof(prog_info);
	int err, curr_prog_fd, prog_fd;

	if (ctx->if_index < 0) {
		ecbpf_warn("Interface not set in ecbpf_ctx\n");
		return -EINVAL;
	}

	// Assume log message was done in unpin_root_program_maps
	unpin_root_program_maps(ctx);

	// Do a replace if there is already something on the interface
	curr_prog_fd = get_current_root_prog_fd(ctx, &prog_info, &prog_info_len);

	if (curr_prog_fd < 0) {
		ecbpf_warn("No XDP program attached to interface '%s'\n", ctx->if_name);
		return 0;
	}

	// Support swaping in another root program.  It is expected that the root loader will
	// load the NOP program as it does with the root array before calling ecbpf__detach_root_program.
	prog_fd = ecbpf_ctx__get_root_prog_fd(ctx); // defaults to -1
	if (prog_fd >= 0) {
		ecbpf_info("Performing XDP program replace.\n");

		if (strcmp(prog_info.name, xstr(ROOT_PROG_NAME))) {
			if(!strcmp(prog_info.name, xstr(ROOT_PROG_NOP_NAME))) {
				ecbpf_warn("XDP Root NOP program appears to already be loaded.\n");
			}
			ecbpf_warn("Replacing unexpected XDP program '%s' with NOP anyway.\n", prog_info.name);
		}

		attach_opts.old_prog_fd = curr_prog_fd;

		// Do the attach
		err = bpf_xdp_attach(ctx->if_index, prog_fd, ctx->xdp_flags &  XDP_FLAGS_REPLACE, &attach_opts);
		if (err) {
			ecbpf_warn("Failed to attach program to interface %s: %s\n\n",
						ctx->if_name, strerror(-err));
			return err;
		}

		ecbpf_info("XDP NOP program loaded in root arrays place.\n");
	} else {
		ecbpf_info("Performing XDP program detach.\n");
		err = bpf_xdp_detach(ctx->if_index, ctx->xdp_flags, NULL);

		if (err) {
			ecbpf_warn("Failed to detach program from interface %s: %s\n",
				ctx->if_name, strerror(-err));
		}
	}

	return 0;
}

/**
 * @brief Make sure the root program array is loaded
 * @param ctx ecbpf_ctx
 *
 * Right now this just checks for the pinned root array
 * map, nothing fancy.  Also makes sure the caller is
 * root since we aren't great about differentiating the
 * non-existance of the map with not being able to read
 * it.
 *
 * @return 0 on success, negative -EACCES on not enough
 * privileges and -ENOENT if the root map doesn't exist.
 */
int ecbpf__check_root_program(struct ecbpf_ctx *ctx) {
	int fd;

	if (geteuid() != 0) {
		ecbpf_warn("Can't check for root program without being root\n");
		return -EACCES;
	}

	fd = ecbpf__get_map_fd(ctx, xstr(ROOT_MAP_NAME));

	if (fd < 0)
		return -ENOENT;

	return 0;
}
/** @} */ // end of root

/** @defgroup map ECBPF Map handling methods
 *  @{
 */
/**
 * @brief Internal helper for map paths in bpf fs.
 * @param ctx ecbpf_ctx
 * @param path pointer to path string
 * @param len length of path string
 * @param map_name Name of map or NULL
 *
 * If map_name is NULL, the path for the namespace is returned.
 *
 * @return 0 on success
 */
static int map_path(struct ecbpf_ctx *ctx, char *path, int len, const char *map_name)
{
	int res;

	if (map_name == NULL) {
		res =
		    snprintf(path, len, "%s/%s", sys_fs_bpf,
			     ecbpf_ctx__namespace(ctx));
	} else {
		res =
		    snprintf(path, len, "%s/%s/%s", sys_fs_bpf,
			     ecbpf_ctx__namespace(ctx), map_name);
	}

	if (res < 0) {
		ecbpf_warn("Something horribly wrong with path\n");
		return -EINVAL;
	}

	if (res >= len) {
		ecbpf_warn("Not enough space in path buffer\n");
		return -ENOMEM;
	}

	return 0;
}

/**
 * @brief Use context namespace to lookup a pinned map fd
 * @param ctx ecbpf_ctx
 * @param map_name Name of map
 *
 * @return map fd or negative number on failure
 */
int ecbpf__get_map_fd(struct ecbpf_ctx *ctx, char *map_name) {
	int err;
	char path[PATH_MAX];
	struct bpf_map *map;
	
	err = map_path(ctx, path, sizeof(path), map_name);
	if (err) {
		return err;
	}

	return ecbpf_get_map_fd(path);
}

/**
 * @brief Pin a map inside a namespace
 * @param ctx ecbpf_ctx
 * @param map_name Name of map or NULL
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__pin_map(struct ecbpf_ctx *ctx, char *map_name) {
	int err;
	int ret = 0;
	char path[PATH_MAX];
	struct bpf_map *map;

	if (ctx->bpf_obj == NULL) {
		ecbpf_warn("Context does not contain a bpf object\n");
		return -EINVAL;
	}

	err = map_path(ctx, path, sizeof(path), map_name);
	if (err) {
		return err;
	}

	map = bpf_object__find_map_by_name(ctx->bpf_obj, map_name);
	if (map == NULL) {
		ecbpf_warn("Failed to find map %s\n", map_name);
		return -ENOENT;
	}

	err = bpf_map__pin(map, path);
	if (err) {
		ecbpf_warn("Failed to pin map %s to %s: %s\n",
					bpf_map__name(map), path, strerror(-err));
		return err;
	}

	return 0;
}


/**
 * @brief Internal helper called by nftw in unpin_root_program_maps.
 */
static int unpin_unlink(const char *fpath, const struct stat *sb,
			int tflag, struct FTW *ftwbuf)
{
	int res;
	ecbpf_info("Unpinning: %s\n", fpath);

	res = remove(fpath);

	if (res) {
		ecbpf_warn("Failed to cleanup map file %s: %m\n", fpath);
	}
	return res;
}


/**
 * @brief Unpin a map.
 * @param ctx ecbpf_ctx
 * @param map_name Name of map
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__unpin_map(struct ecbpf_ctx *ctx, char *map_name)
{
	int err;
	int res = 0;
	char path[PATH_MAX];

	err = map_path(ctx, path, sizeof(path), map_name);
	if (err) {
		return err;
	}

	err = unlink(path);
	if (err) {
		ecbpf_warn("Failed to unpin map %s: %m", path);
		return -errno;
	}

	return 0;
}
/** @} */ // end of map

/** @defgroup subprog ECBPF Subprogram handling methods
 *  @{
 */
/**
 * @brief Load a subprogram into the context.
 * @param ctx ecbpf_ctx
 * @param filename ELF file containing the subprogram
 *
 * Attach and load have been broken into two so that map pinning
 * can be performed.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_open(struct ecbpf_ctx *ctx, char *filename)
{
	int err = 0;
	char resolved_filename[PATH_MAX];
	struct bpf_object *obj;

	// Resolve the filename
	err = resolve_filename(filename, resolved_filename, sizeof(resolved_filename));
	if (err) {
		return err;
	}

	// make sure rlimits are set
	err = ecbpf_set_rlimit();
	if (err)
		return err;

	if (ctx->bpf_obj) {
		ecbpf_warn("Program already loaded into conext\n");
		return -EINVAL;
	}

	obj = bpf_object__open_file(resolved_filename, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		ecbpf_warn("Failed to load bpf object: %s\n", strerror(err));
		return err;
	}

	ctx->bpf_obj = obj;

	return 0;
}

/**
 * @brief Remove subprogram from current context
 * @param ctx ecbpf_ctx
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_close(struct ecbpf_ctx *ctx)
{
	int err = 0;

	if (!ctx->bpf_obj) {
		ecbpf_warn("Attempt to unload program from empty conext\n");
		return -EINVAL;
	}

	bpf_object__close(ctx->bpf_obj);
	ctx->bpf_obj = NULL;

	return 0;
}

/**
 * @brief Plumb in a pinned map
 * @param ctx ecbpf_ctx
 * @param map_name Name of map
 *
 * Uses context namespace to plumb in a map present
 * in the bpf fs into the program object present in the
 * ecbpf_ctx.
 *
 * @return fd of reused map, negative on failure.
 */
int ecbpf__subprogram_reuse_map(struct ecbpf_ctx *ctx, char *map_name) {
	char path[PATH_MAX];
	int fd;
	int err;
	struct bpf_map *map;

	if (!ctx->bpf_obj) {
		ecbpf_warn("No subprogram loaded into context\n");
		return -EINVAL;
	}

	err = map_path(ctx, path, sizeof(path), map_name);
	if (err) {
		return err;
	}

	fd = ecbpf_get_map_fd(path);

	if (fd < 0) {
		ecbpf_warn("Map %s is not present in the bpf fs\n", path);
		return fd;
	}

	map = bpf_object__find_map_by_name(ctx->bpf_obj, map_name);
	if (map == NULL) {
		ecbpf_warn("Map %s not found in program object\n", map_name);
		return -ENOENT;
	}

	err = bpf_map__reuse_fd(map, fd);
	if (err) {
		ecbpf_warn("Failed to reuse map fd\n");
		return err;
	}

	return fd;
}

/**
 * @brief Internal helper to validate slot number
 *
 * @return 0 on success, negative on failure.
 */
static int validate_subprogram_slot(int slot)
{
	if (slot >= SUBPROGRAM_MAX || slot < 0) {
		ecbpf_warn("Attempt to load into invalid slot: %i > max of %i\n", slot, SUBPROGRAM_MAX - 1);
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief Internal helper to get the program array fd for our context
 *
 * @return prog array fd on success, negative on failure.
 */
static int get_prog_array_fd(struct ecbpf_ctx *ctx) {
	int err;
	int fd;
	char path[PATH_MAX];

	err = map_path(ctx, path, sizeof(path), xstr(ROOT_MAP_NAME));
	if (err) {
		return err;
	}

	fd = ecbpf_get_map_fd(path);

	return fd;
}


/**
 * @brief Put subprogram into prog array
 * @param ctx ecbpf_ctx
 * @param prog_name Name of subprogram
 * @param slot Slot number for program
 *
 * To udate an existing program, make sure to do ecbpf_ctx__set_subprogram_update(ctx, true);
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_attach(struct ecbpf_ctx *ctx, char *prog_name, int slot)
{
	int res;
	int err;
	int xdpcap_map_fd, stats_map_fd, prog_array_fd, sample_map_fd;
	int prog_fd;
	struct bpf_program *prog;

	if (!ctx->bpf_obj) {
		ecbpf_warn("Attempt to load from empty context\n");
		return -EINVAL;
	}

	err = validate_subprogram_slot(slot);
	if (err)
		return err;

	// Make sure the slot is empty if we aren't updating
	if (!ctx->subprogram_update && !ctx->subprogram_test) {
		if(ecbpf__subprogram_slot_prog_id(ctx, slot) >= 0) {
			ecbpf_warn("Program already attached to slot %i and subprogram_update flag not set\n", slot);
			return -EINVAL;
		}
	}

	prog = bpf_object__find_program_by_name(ctx->bpf_obj, prog_name);
	if (prog == NULL) {
		ecbpf_warn("Object does not contain a program named %s\n", prog_name);
		return -ENOENT;
	}

	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	// Pin required maps
	if (!ctx->subprogram_test) { // Skip these reuses when in test mode...
		prog_array_fd = ecbpf__subprogram_reuse_map(ctx, xstr(ROOT_MAP_NAME));
		if (prog_array_fd < 0) {
			ecbpf_warn("Subprograms must contain the root program array\n");
			return -ENOENT;
		}

		stats_map_fd = ecbpf__subprogram_reuse_map(ctx, xstr(XDP_STATS_MAP_NAME));
		if (stats_map_fd < 0) {
			ecbpf_info("Subprogram does not have an %s map.  "
					   "Not instrumented for xdp statistics\n", xstr(XDP_STATS_MAP_NAME));
			return -ENOENT;
		}

		xdpcap_map_fd = ecbpf__subprogram_reuse_map(ctx, xstr(XDPCAP_MAP_NAME));
		if (xdpcap_map_fd < 0) {
			ecbpf_info("Subprogram does not have an %s map.  "
					   "Not instrumented for xdpcap\n", xstr(XDPCAP_MAP_NAME));
			return -ENOENT;
		}

		sample_map_fd = ecbpf__subprogram_reuse_map(ctx, xstr(XDP_SAMPLER_MAP_NAME));
		if (sample_map_fd < 0) {
			ecbpf_info("Subprogram does not have an %s map.  "
					   "Not instrumented for xdp sampling\n", xstr(XDP_SAMPLER_MAP_NAME));
			return -ENOENT;
		}
	}

	// load the object into the kernel now
	err = bpf_object__load(ctx->bpf_obj);
	if (err) {
		ecbpf_warn("Failed to load bpf object\n");
		return err;
	}

	// Pin requested maps
	struct pinned_map *cur = ctx->pinned_maps;

	while (cur) {
		if (ctx->subprogram_update) {
			err = ecbpf__subprogram_reuse_map(ctx, cur->map);
		} else {
			err = ecbpf__pin_map(ctx, cur->map);
		}

		if (err)
			return err;

		cur = cur->next;
	}

	// Get fd of program
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		ecbpf_warn("Failed to get program fd\n");
		return prog_fd;
	}

	// store the last subprogram fd
	ctx->sub_prog_fd = prog_fd;

	// point the prog array
	if (!ctx->subprogram_test) {
		err = bpf_map_update_elem(prog_array_fd, &slot, &prog_fd,
					  BPF_ANY);
		if (err) {
			ecbpf_warn("Failed to update progarray map\n");
			return err;
		}
	}

	return 0;
}

/**
 * @brief Remove subprogram from prog array
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_detach(struct ecbpf_ctx *ctx, int slot)
{
	int err;
	int res;
	int prog_array_fd;
	int prog_fd;
	struct bpf_map *map;
	struct pinned_map *cur;

	// Skip root map removal if we are testing
	if (ctx->subprogram_test)
		goto unpin;

	/*
	 * Remove from root map if not in test mode (see goto unpin)
	 */
	err = validate_subprogram_slot(slot);
	if (err)
		return err;

	prog_array_fd = get_prog_array_fd(ctx);
	if (prog_array_fd < 0) {
		return prog_array_fd;
	}

	err = bpf_map_delete_elem(prog_array_fd, &slot);
	if (err) {
		ecbpf_warn("Failed to update progarray map\n");
		return err;
	}

unpin:
	// unpin requested maps
	cur = ctx->pinned_maps;

	while (cur) {
		err = ecbpf__unpin_map(ctx, cur->map);

		// TODO: See if we want to bubble up failures from unpinning or bail.
		// I figure best effort is the way to go.
		if (err)
			ecbpf_warn("Failed to unpin map, attempting to unpin others\n");

		cur = cur->next;
	}

	return 0;
}

/**
 * @brief Return the program id for a particular slot
 * @param ctx ecbpf_ctx
 * @param slot Slot number to look at
 *
 * @return id >= 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_prog_id(struct ecbpf_ctx *ctx, int slot) {
	int err;
	int prog_array_fd;
	int prog_id;
	struct bpf_map *map;

	err = validate_subprogram_slot(slot);
	if (err)
		return err;

	prog_array_fd = get_prog_array_fd(ctx);
	if (prog_array_fd < 0) {
		return prog_array_fd;
	}

	err = bpf_map_lookup_elem(prog_array_fd, &slot, &prog_id);
	if (err) {
		return err;
	}

	return prog_id;
}

/**
 * @brief Return the program fd for a particular slot
 * @param ctx ecbpf_ctx
 * @param slot Slot number to look at
 *
 * @return fd >= 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_prog_fd(struct ecbpf_ctx *ctx, int slot) {
	int prog_array_fd;
	int prog_id;
	int prog_fd;
	struct bpf_map *map;

	prog_id = ecbpf__subprogram_slot_prog_id(ctx, slot);
	if (prog_id < 0)
		return prog_id;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0) {
		ecbpf_warn("Failed to translate program id %i to fd: (%d) %m\n", prog_id, errno);
		return prog_fd; // might as well be explicit than fall through.
	}

	return prog_fd;
}

/**
 * @brief Get the full struct bpf_prog_info of a subprogram in a slot.
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 * @param prog_info Pointer to struct bpf_prog_info, caller allocated
 * @param prog_info_len Pointer to length of struct bpf_prog_info.
 *
 * Note: bpf_prog_info expanded after 4.15 kernel, so all additional
 * fields must be pre-zeroed and post-call only fields common to all
 * versions may be used without checking for validity.
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_bpf_prog_info(struct ecbpf_ctx *ctx, int slot, struct bpf_prog_info *prog_info, uint32_t *prog_info_len)
{
	int err = 0;
	int prog_fd;

	prog_fd = ecbpf__subprogram_slot_prog_fd(ctx, slot);
	if (prog_fd < 0) {
		return prog_fd;
	}

	memset(prog_info, 0, *prog_info_len);
	err = bpf_obj_get_info_by_fd(prog_fd, prog_info, prog_info_len);
	if (err) {
		ecbpf_warn("Unable to get XDP program info for slot %i, error: (%d) %m\n", slot, errno);
		return err;
	}

	return 0;
}

/**
 * @brief Get the name of a subprogram in a slot.
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 * @param dst Destination buffer to copy name into
 * @param len Length of destination buffer
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_name(struct ecbpf_ctx *ctx, int slot, char *dst, size_t len)
{
	int err;
 	struct bpf_prog_info prog_info;
	uint32_t prog_info_len = sizeof(prog_info);

	err = ecbpf__subprogram_slot_bpf_prog_info(ctx, slot, &prog_info, &prog_info_len);
	if (err)
		return err;

	if (prog_info.name[0] == '\0')
		ecbpf_info("Program in slot %i does not have a name\n", slot);

	memset(dst, 0, len);
	strncpy(dst, prog_info.name, len);
	if (dst[len - 1] != '\0') {
		ecbpf_warn("Supplied dst buffer too small for program name\n");
		dst[len - 1] = '\0';
		return -ENAMETOOLONG;
	}

	return 0;
}

/**
 * @brief Get the load time of a subprogram in a slot.
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 * @param dst Pointer to time_t, caller allocated
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_load_time(struct ecbpf_ctx *ctx, int slot, time_t *dst)
{
	int err;
	struct timespec realtime_ts;
	struct timespec boottime_ts;
    struct bpf_prog_info prog_info;
	uint32_t prog_info_len = sizeof(prog_info);

	err = ecbpf__subprogram_slot_bpf_prog_info(ctx, slot, &prog_info, &prog_info_len);
	if (err)
		return err;

	// Collect time system was booted and current time
	err = clock_gettime(CLOCK_BOOTTIME, &boottime_ts);
	if (err) {
		ecbpf_warn("Failed to get CLOCK_BOOTTIME\n");
		return -errno;
	}

	err = clock_gettime(CLOCK_REALTIME, &realtime_ts);
	if (err) {
		ecbpf_warn("Failed to get CLOCK_REALTIME\n");
		return -errno;
	}

	// prog_info.load_time is nsecs since boot time
	*dst = (realtime_ts.tv_sec - boottime_ts.tv_sec) + (prog_info.load_time / 1000000000ull);
	
	return 0;
}

/**
 * @brief Get the xdp statistics of a subprogram in a slot.
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 * @param stats Pointer to struct xdp_stats, caller allocated
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_statistics(struct ecbpf_ctx *ctx, int slot, struct xdp_stats *stats) {
	int err = 0;
	int fd;
	int np = libbpf_num_possible_cpus(); // XDP_STATS_MAP_NAME is a per cpu array for concurrency reasons;
	struct xdp_stats *np_stats;

	np_stats = malloc(sizeof(struct xdp_stats) * np);
	if (!np_stats)
		return -ENOMEM;

	err = ecbpf__check_root_program(ctx);
	if (err) {
		ecbpf_warn("Root ecbpf program not attached.\n");
		err = -ENOENT;
		goto done;
	}

	fd = ecbpf__get_map_fd(ctx, xstr(XDP_STATS_MAP_NAME));
	if (fd < 0) {
		// Note that we assume the map is pinned already
		ecbpf_warn("Unable to get XDP_STATS_MAP_NAME file descriptor.\n");
		err = fd;
		goto done;
	}

	// Zero out the stats in case we return after a failed lookup
	for (int action = 0; action < STAT_XDP_MAX; action++) {
		stats->action_count[action] = 0;
	}

	err = bpf_map_lookup_elem(fd, &slot, np_stats);
	if (err) {
		// Make it so we can loop through slots.  Stats are zeroed above,
		// so we are done here.
		err = 0;
		goto done;
	}

	// Sum the stats.
	for (int action = 0; action < STAT_XDP_MAX; action++) {
		for (int cpu = 0; cpu < np; cpu++) {
			stats->action_count[action] += np_stats[cpu].action_count[action];
		}
	}

done:
	free(np_stats);

	return err;
}

/**
 * @brief Clear the xdp statistics of a subprogram in a slot.
 * @param ctx ecbpf_ctx
 * @param slot Slot number for program
 *
 * @return 0 on success, negative on failure.
 */
int ecbpf__subprogram_slot_statistics_clear(struct ecbpf_ctx *ctx, int slot) {
	int err = 0;
	int fd;
	int np = libbpf_num_possible_cpus(); // XDP_STATS_MAP_NAME is a per cpu array for concurrency reasons;
	struct xdp_stats *np_stats;

	np_stats = malloc(sizeof(struct xdp_stats) * np);
	if (!np_stats)
		return -ENOMEM;

	err = ecbpf__check_root_program(ctx);
	if (err) {
		ecbpf_warn("Root ecbpf program not attached.\n");
		err = -ENOENT;
		goto done;
	}

	fd = ecbpf__get_map_fd(ctx, xstr(XDP_STATS_MAP_NAME));
	if (fd < 0) {
		// Note that we assume the map is pinned already
		ecbpf_warn("Unable to get XDP_STATS_MAP_NAME file descriptor.\n");
		err = fd;
		goto done;
	}

	// Zero the stats (could also use calloc, but this makes the structure explicit).
	for (int action = 0; action < STAT_XDP_MAX; action++) {
		for (int cpu = 0; cpu < np; cpu++) {
			np_stats[cpu].action_count[action] = 0;
		}
	}

	err = bpf_map_update_elem(fd, &slot, np_stats, BPF_ANY);
	if (err) {
		goto done;
	}

done:
	free(np_stats);

	return err;
}
/** @} */ // end of subprog

