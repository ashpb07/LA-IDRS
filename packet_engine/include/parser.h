#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_IP_STR_LEN 16

typedef struct {
    char     src_ip[MAX_IP_STR_LEN];
    char     dst_ip[MAX_IP_STR_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;      /* IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP */
    uint8_t  tcp_flags;     /* only valid when protocol == IPPROTO_TCP  */
    uint16_t payload_len;
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
} packet_meta_t;

/* TCP flag masks */
#define FLAG_FIN  0x01
#define FLAG_SYN  0x02
#define FLAG_RST  0x04
#define FLAG_PSH  0x08
#define FLAG_ACK  0x10
#define FLAG_URG  0x20

int parse_packet(const u_char *raw, uint32_t caplen,
                 uint32_t ts_sec, uint32_t ts_usec,
                 packet_meta_t *out);

#endif /* PARSER_H */