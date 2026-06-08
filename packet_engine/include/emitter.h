#ifndef EMITTER_H
#define EMITTER_H

#include "parser.h"

/* Emitter sends packet_meta_t over a UNIX domain socket to the Python detection engine */

#define SOCKET_PATH "/tmp/netsentinel.sock"

typedef struct {
    int sock_fd;
} emitter_ctx_t;

int  emitter_init(emitter_ctx_t *ctx);
int  emitter_send(emitter_ctx_t *ctx, const packet_meta_t *meta);
void emitter_destroy(emitter_ctx_t *ctx);

#endif /* EMITTER_H */