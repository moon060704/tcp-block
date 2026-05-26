#ifndef ANSHEADER_H
#define ANSHEADER_H

#include <stdint.h>
#include <pcap.h>

#define MAC_ALEN 6

#define ETH_P_ARP  0x0806
#define ETH_P_IPV4 0x0800

#define IP_VERSION_IPV4 4
#define IP_PROTOCOL_TCP 6

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#pragma pack(push, 1)

typedef struct {
    uint8_t m[MAC_ALEN];
} Mac;

typedef struct {
    uint32_t ip;
} Ip;

typedef struct {
    Mac dst_mac;
    Mac src_mac;
    uint16_t eth_type;
} EthHdr;

typedef struct {
    uint8_t  vhl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    Ip       ip_src;
    Ip       ip_dst;
} Ipv4Hdr;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  hlen_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} TcpHdr;

typedef struct {
    Ip       src_ip;
    Ip       dst_ip;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t tcp_len;
} TcpPseudoHdr;

typedef struct {
    EthHdr  eth;
    Ipv4Hdr ip;
    TcpHdr  tcp;
} EthIpTcpPacket;

#pragma pack(pop)

static inline uint8_t ipv4_version(const Ipv4Hdr* ip)
{
    return ip->vhl >> 4;
}

static inline uint8_t ipv4_header_len(const Ipv4Hdr* ip)
{
    return (ip->vhl & 0x0f) * 4;
}

static inline uint8_t tcp_header_len(const TcpHdr* tcp)
{
    return (tcp->hlen_reserved >> 4) * 4;
}

static inline void set_ipv4_vhl(Ipv4Hdr* ip, uint8_t version, uint8_t hlen)
{
    ip->vhl = (version << 4) | (hlen / 4);
}

static inline void set_tcp_hlen(TcpHdr* tcp, uint8_t hlen)
{
    tcp->hlen_reserved = (hlen / 4) << 4;
}

void usage();

int get_my_info(const char* dev, Mac* mac, Ip* ip);

uint16_t calc_checksum(const void* data, int len);

uint16_t calc_ip_checksum(Ipv4Hdr* ip);

uint16_t calc_tcp_checksum(
    const Ipv4Hdr* ip,
    const TcpHdr* tcp,
    const uint8_t* payload,
    uint16_t payload_len
);

#endif
