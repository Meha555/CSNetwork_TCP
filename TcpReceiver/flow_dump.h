#pragma once
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#define WIN32
#define WPCAP
#define HAVE_REMOTE
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")

/*set the C++ head files*/
#include <iostream>
#include <stdio.h>
#include <map>
#include <string>
#include <iomanip>
#include <sstream>

/*set the wpcap head files*/
#include "pcap.h"
#include <WinSock2.h>


#define DIVISION "--------------------"
#define B_DIVISION "============="

/*header structure*/
struct ip_v4_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_v6_address {
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

struct ip_v4_header {
    u_char ver_ihl;             // Version (4 bits) + Internet header length (4 bits)
    u_char tos;                 // Type of service
    u_short tlen;               // Total length
    u_short identification;     // Identification
    u_short flags_fo;           // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;                 // Time to live
    u_char proto;               // Protocol
    u_short checksum;           // Header checksum
    ip_v4_address src_ip_addr;  // Source address
    ip_v4_address des_ip_addr;  // Destination address
    u_int op_pad;               // Option + Padding
};

struct ip_v6_header {
    uint32_t ver_trafficclass_flowlabel;
    u_short payload_len;
    u_char next_head;
    u_char ttl;
    ip_v6_address src_ip_addr;
    ip_v6_address dst_ip_addr;
};

struct arp_header {
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_length;
    u_char protocol_length;
    u_short operation_code;
    mac_address source_mac_addr;
    ip_v4_address source_ip_addr;
    mac_address des_mac_addr;
    ip_v4_address des_ip_addr;
};

struct tcp_header {
    u_short sport;
    u_short dport;
    u_int sequence;
    u_int acknowledgement;
    u_char offset;
    u_char flags;
    u_short windows;
    u_short checksum;
    u_short urgent_pointer;
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

 /* 4 bytes IP address */
typedef struct ip_v4_address ip_v4_address;

/* 16 bytes IP address */
typedef struct ip_v6_address ip_v6_address;

/*8 bytes MAC addresss*/
typedef struct mac_address mac_address;

/*ethernet header*/
typedef struct ethernet_header ethernet_header;

/* IPv4 header */
typedef struct ip_v4_header ip_v4_header;

/*IPv6 header*/
typedef struct ip_v6_header ip_v6_header;

/*arp header*/
typedef struct arp_header arp_header;

/*TCP header*/
typedef struct tcp_header tcp_header;

/* UDP header*/
typedef struct udp_header udp_header;

/*ICMP header*/
typedef struct icmp_header icmp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the ethernet packet*/
void ethernet_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the IPv4 packet*/
void ip_v4_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the IPv6 packet*/
void ip_v6_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the arp packet*/
void arp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the udp packet*/
void udp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the tcp packet*/
void tcp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*analysis the icmp packet*/
void icmp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*count the package with c++ std::map*/
void add_to_map(std::map<std::string, int>& counter, ip_v4_address ip);
void add_to_map(std::map<std::string, int>& counter, ip_v6_address ip);

/*print the map info*/
void print_map(std::map<std::string, int> counter);
