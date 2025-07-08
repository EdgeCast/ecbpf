#define _GNU_SOURCE // asprintf, pthread_setname_np
#include <err.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

#include "xzmq.h"

void *xzmq_publisher(void *data);

struct xzmq_ctx {
	char url[1024];
	_Atomic int stop;
	bool has_thread;
	pthread_t tid;
	pthread_mutex_t thread_lock;
};

struct xzmq_ctx *xzmq_ctx_new(char *port) {
	struct xzmq_ctx *ctx = calloc(1, sizeof(struct xzmq_ctx));
	if (ctx == NULL)
		errx(EXIT_FAILURE, "Failed to allocate memory in xzmq_ctx_new");

	snprintf(ctx->url, sizeof(ctx->url), "tcp://127.0.0.1:%s", port);

	ctx->has_thread = false;

	if (pthread_mutex_init(&ctx->thread_lock, NULL) != 0) {
        fprintf(stderr, "Failed to init xzmq mutex: %m\n");
		free(ctx);
		return NULL;
    }
	
	return ctx;
}

void xzmq_ctx_free(struct xzmq_ctx *ctx) {
	pthread_mutex_lock(&ctx->thread_lock);
	if (ctx->has_thread)
		errx(EXIT_FAILURE, "xdp_zmq_ctx_free: Attempt to free running context.");
	pthread_mutex_unlock(&ctx->thread_lock);

	free(ctx);
}

void xzmq_start(struct xzmq_ctx *ctx) {
	int res;

	pthread_mutex_lock(&ctx->thread_lock);

	res = pthread_create(&ctx->tid, NULL, xzmq_publisher, (void*)ctx);
	if (res) {
		errx(EXIT_FAILURE, "Failed to start xzmq_publisher thread: %s", strerror(res));
	}

	ctx->has_thread = true;

	res = pthread_setname_np(ctx->tid, "xzmq_pub");
	if (res) {
		errx(EXIT_FAILURE, "Failed to name xzmq_publisher thread: %s", strerror(res));
	}

	pthread_mutex_unlock(&ctx->thread_lock);
}

void xzmq_stop(struct xzmq_ctx *ctx) {
	int res;

	pthread_mutex_lock(&ctx->thread_lock);
	ctx->stop++;

	printf("Waiting for zmq publisher to exit\n");
	res = pthread_join(ctx->tid, NULL);
	if (res) {
		errx(EXIT_FAILURE, "Joining thread zmq_publisher failed: %m\n");
	}

	ctx->has_thread = false;
	pthread_mutex_unlock(&ctx->thread_lock);
}

void *xzmq_publisher(void *data) {
	struct xzmq_ctx *ctx = (struct xzmq_ctx *) data;
	int res;
	void *pub_sock, *pull_sock;

    pub_sock = zmq_socket(zmq_context, ZMQ_PUB);
    res = zmq_bind(pub_sock, ctx->url);

	if (res != 0) {
		err(EXIT_FAILURE, "Failed to setup zmq publisher socket");
	}

	// Setup the pull socket
	pull_sock = zmq_socket(zmq_context, ZMQ_PULL);

	int timeout = 1000;
	res = zmq_setsockopt (pull_sock, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
	if (res != 0) {
		err(EXIT_FAILURE, "Failed set zmq pull socket options");
	}

	res = zmq_bind(pull_sock, PUSH_PULL_URL);
	if (res != 0) {
		err(EXIT_FAILURE, "Failed to connect zmq pull socket");
	}

	uint8_t buf[4096];
	int size;

	for(;;) {
		size = zmq_recv(pull_sock, buf, sizeof(buf), 0);

		if (ctx->stop)
			break;

		if (size < 0) {
			if (errno == EAGAIN)
				continue;
			else
				err(EXIT_FAILURE, "Failed recv on pull socket: %m");
		}

		size = zmq_send(pub_sock, buf, size, 0);
		if (size < 0) {
			errx(EXIT_FAILURE, "zmq_send failed with %i: %m", size);
		}
	}

	fprintf(stderr, "zmq_publisher: shutting down\n");
	zmq_close(pull_sock);
	zmq_close(pub_sock);
	pthread_exit(NULL);
}
