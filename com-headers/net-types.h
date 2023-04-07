#pragma once
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#define WIN32
#define WPCAP
#define HAVE_REMOTE
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "ws2_32.lib")

#include <WinSock2.h>
#include <pcap.h>
#include <stdio.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

#define DIVISION "--------------------"
#define B_DIVISION "============="

#pragma pack(1)  // 按一个字节内存对齐

// IPv4点分十进制格式(适用于输入)
struct ipv4_num {
    u_short ip1, ip2, ip3, ip4;
};

struct ipv4_address {
    union {
        struct {
            u_char byte1;
            u_char byte2;
            u_char byte3;
            u_char byte4;
        } dot_decimal_fmt;
        u_long binary_fmt;
    } ipv4_fmt;
#define dot_fmt ipv4_fmt.dot_decimal_fmt
#define bin_fmt ipv4_fmt.binary_fmt
    void operator=(ipv4_address& t) {
        this->bin_fmt = t.bin_fmt;
    }
};

struct ipv6_address {
    u_short part1;
    u_short part2;
    u_short part3;
    u_short part4;
    u_short part5;
    u_short part6;
    u_short part7;
    u_short part8;
};

struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
};

struct ethernet_header {
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
};

struct ipv4_header {
#define IPV4_HDR_LEN 28
    u_char ver_hlen;           // Version (4 bits) + Internet header length (4 bits)
    u_char tos;                // Type of service
    u_short tlen;              // Total length
    u_short id;                // Identification
    u_short flags_offset;      // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;                // Time to live
    u_char protocol;           // Protocol
    u_short checksum;          // Header checksum
    ipv4_address src_ip_addr;  // Source address
    ipv4_address des_ip_addr;  // Destination address
    // u_int op_pad;               // Option + Padding
};

struct ipv6_header {
#define IPV6_HDR_LEN 40
    uint32_t ver_trafficclass_flowlabel;
    u_short payload_len;
    u_char next_head;
    u_char ttl;
    ipv6_address src_ip_addr;
    ipv6_address dst_ip_addr;
};

struct arp_header {
#define ARP_FRME_LEN 28
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_length;
    u_char protocol_length;
    u_short operation_code;
    mac_address src_mac_addr;
    ipv4_address src_ip_addr;
    mac_address des_mac_addr;
    ipv4_address des_ip_addr;
};

struct arp_packet {
#define ARP_PKT_LEN 42
    ethernet_header ed;  // 以太网首部
    arp_header ah;       // ARP字段
};

struct tcp_header {
#define TCP_HDR_LEN 20
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urg;
};

// TCP伪首部（12B）
struct psd_tcp_header {
#define PSDTCP_HDR_LEN 12
    ipv4_address src_addr;  // 源IP地址  4字节
    ipv4_address des_addr;  // 目的IP地址 4字节
    u_char zero;            // 填充位  1字节
    u_char protcol;         // 协议号  1字节
    u_short tcp_len;        // TCP包长度 2字节
};

struct udp_header {
    u_short sport;     // Source port
    u_short dport;     // Destination port
    u_short len;       // Datagram length
    u_short checksum;  // Checksum
};
struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short sequence;
};

#pragma pack()  // 取消按一个字节内存对齐

