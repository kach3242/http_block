#include <stdint.h>

#define ipv4 0x0800

struct eth_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t eth_type;
};

struct ip_header{
    uint8_t ipv4_len;
    uint8_t tos;
    uint16_t packet_len;
    uint8_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t pid;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
};

struct tcp_header{
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t hlen;
    uint8_t flag;
    uint16_t wsize;
    uint16_t checksum;
    uint16_t urg_pointer;
};
