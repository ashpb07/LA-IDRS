#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "../include/parser.h"

int parse_packet(const u_char *raw, uint32_t caplen,
                 uint32_t ts_sec, uint32_t ts_usec,
                 packet_meta_t *out) {
    if (!raw || !out) return -1;

    /* Skip Ethernet header (14 bytes) */
    if (caplen < sizeof(struct ethhdr)) return -1;
    const struct ethhdr *eth = (const struct ethhdr *)raw;

    /* Only handle IPv4 */
    if (ntohs(eth->h_proto) != ETH_P_IP) return -1;

    const u_char *ip_raw = raw + sizeof(struct ethhdr);
    uint32_t remaining = caplen - sizeof(struct ethhdr);
    if (remaining < sizeof(struct iphdr)) return -1;

    const struct iphdr *iph = (const struct iphdr *)ip_raw;
    uint32_t ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || remaining < ip_hdr_len) return -1;

    /* Fill basic IP fields */
    inet_ntop(AF_INET, &iph->saddr, out->src_ip, MAX_IP_STR_LEN);
    inet_ntop(AF_INET, &iph->daddr, out->dst_ip, MAX_IP_STR_LEN);
    out->protocol      = iph->protocol;
    out->timestamp_sec  = ts_sec;
    out->timestamp_usec = ts_usec;
    out->src_port      = 0;
    out->dst_port      = 0;
    out->tcp_flags     = 0;
    out->payload_len   = 0;

    const u_char *transport = ip_raw + ip_hdr_len;
    uint32_t transport_len  = remaining - ip_hdr_len;

    if (iph->protocol == IPPROTO_TCP) {
        if (transport_len < sizeof(struct tcphdr)) return -1;
        const struct tcphdr *tcph = (const struct tcphdr *)transport;
        out->src_port    = ntohs(tcph->source);
        out->dst_port    = ntohs(tcph->dest);
        out->tcp_flags   = (uint8_t)(tcph->fin  |
                                     (tcph->syn  << 1) |
                                     (tcph->rst  << 2) |
                                     (tcph->psh  << 3) |
                                     (tcph->ack  << 4) |
                                     (tcph->urg  << 5));
        uint32_t tcp_hdr_len = tcph->doff * 4;
        out->payload_len = (transport_len > tcp_hdr_len)
                         ? (uint16_t)(transport_len - tcp_hdr_len) : 0;
    } else if (iph->protocol == IPPROTO_UDP) {
        if (transport_len < sizeof(struct udphdr)) return -1;
        const struct udphdr *udph = (const struct udphdr *)transport;
        out->src_port    = ntohs(udph->source);
        out->dst_port    = ntohs(udph->dest);
        out->payload_len = (ntohs(udph->len) > sizeof(struct udphdr))
                         ? (uint16_t)(ntohs(udph->len) - sizeof(struct udphdr)) : 0;
    }
    /* ICMP and others: ports/flags remain 0 */

    return 0;
}
