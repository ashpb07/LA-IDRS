#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../include/emitter.h"

int emitter_init(emitter_ctx_t *ctx) {
    if (!ctx) return -1;

    ctx->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx->sock_fd < 0) {
        perror("[emitter] socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* Retry until the Python server is ready */
    int retries = 10;
    while (retries-- > 0) {
        if (connect(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            fprintf(stdout, "[emitter] Connected to detection engine at %s\n", SOCKET_PATH);
            return 0;
        }
        perror("[emitter] connect (retrying)");
        sleep(1);
    }

    fprintf(stderr, "[emitter] Could not connect to detection engine.\n");
    close(ctx->sock_fd);
    ctx->sock_fd = -1;
    return -1;
}

int emitter_send(emitter_ctx_t *ctx, const packet_meta_t *meta) {
    if (!ctx || ctx->sock_fd < 0 || !meta) return -1;

    ssize_t sent = send(ctx->sock_fd, meta, sizeof(packet_meta_t), MSG_NOSIGNAL);
    if (sent != (ssize_t)sizeof(packet_meta_t)) {
        perror("[emitter] send");
        return -1;
    }
    return 0;
}

void emitter_destroy(emitter_ctx_t *ctx) {
    if (ctx && ctx->sock_fd >= 0) {
        close(ctx->sock_fd);
        ctx->sock_fd = -1;
    }
}
