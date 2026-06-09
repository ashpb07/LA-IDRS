#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <stdint.h>

#define SNAP_LEN        65535
#define PROMISC_MODE    1
#define READ_TIMEOUT_MS 1000
#define MAX_IFACE_LEN   64

typedef struct {
    char interface[MAX_IFACE_LEN];
    pcap_t *handle;
} capture_ctx_t;

int  capture_init(capture_ctx_t *ctx, const char *iface);
void capture_start(capture_ctx_t *ctx, pcap_handler callback, u_char *user_data);
void capture_stop(capture_ctx_t *ctx);
void capture_destroy(capture_ctx_t *ctx);

#endif /* CAPTURE_H */
