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

// IPv4结构体，适用于输出与存储
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
    void operator=(const ipv4_address& t) {
        this->bin_fmt = t.bin_fmt;
    }
    operator in_addr() {
        in_addr t;
        t.S_un.S_addr = this->bin_fmt;
        return t;
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
    mac_address des_mac_addr;  // 目的MAC地址6B
    mac_address src_mac_addr;  // 源MAC地址6B
    u_short type;              // 帧类型
};

struct ipv4_header {
#define IPV4_HDR_LEN 20
    u_char ver_hlen;           // 版本(4bit) + 首部长度(4bit)
    u_char tos;                // 服务类型
    u_short tlen;              // 总长度(首部长度+数据部分的长度)
    u_short id;                // id标识
    u_short flags_offset;      // 标志(3bit) + 片偏移(13bit)
    u_char ttl;                // 生存时间TTL
    u_char protocol;           // 协议类型
    u_short checksum;          // IP首部检验和
    ipv4_address src_ip_addr;  // 源IP地址
    ipv4_address des_ip_addr;  // 目的IP地址
    // u_int op_pad;               // 可选字段和填充位
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
    u_short hardware_type;     // 硬件类型2B
    u_short protocol_type;     // 协议类型2B
    u_char hardware_length;    // MAC地址长度1B
    u_char protocol_length;    // 协议地址长度1B
    u_short operation_code;    // 操作码2B
    mac_address src_mac_addr;  // 源MAC地址6B
    ipv4_address src_ip_addr;  // 源IP地址4B
    mac_address des_mac_addr;  // 目的MAC地址6B
    ipv4_address des_ip_addr;  // 目的IP地址4B
};

struct arp_packet {
#define ARP_PKT_LEN 42
    ethernet_header ed;  // 以太网首部
    arp_header ah;       // ARP字段
};

struct tcp_header {
#define TCP_HDR_LEN 20
    u_short sport;     // 源端口
    u_short dport;     // 目的端口
    u_int seq;         // 序号
    u_int ack;         // 确认号
    u_char offset;     // 4bit的数据偏移+4bit的保留位0
    u_char flags;      // 2bit的保留位0+6bit的flags
    u_short window;    // 窗口大小
    u_short checksum;  // TCP检验和
    u_short urg;       // 紧急指针
    // u_int op_pad;               // 可选字段和填充位
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
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
};
struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short sequence;
};

#pragma pack()  // 取消按一个字节内存对齐
