#pragma once
#include <pcap.h>
#include <inaddr.h>
#include "utils.h"
#pragma pack(1)     // 按一个字节内存对齐

// 以太网帧头部（14B）
struct EthernetHeader {
#define EN_HDR_LEN 14
    u_char dest_mac[6];
    u_char source_mac[6];
    u_short ether_type;
};

// ARP帧结构（28B）
struct ArpFrame {
#define ARP_FRME_LEN 28
    u_short hardware_type;     // 硬件类型
    u_short protocol_type;     // 协议类型
    u_char hardware_addr_len;   // 硬件地址长度
    u_char protocol_addr_len;   // 协议地址长度
    u_short operation_field;   // 操作字段
    u_char source_mac_addr[6];  // 源mac地址
    u_long source_ip_addr;      // 源ip地址
    u_char dest_mac_addr[6];    // 目的mac地址
    u_long dest_ip_addr;          // 目的ip地址
};

// arp包结构
struct ArpPacket {
#define ARP_PKT_LEN 42
    EthernetHeader ed;  // 以太网首部
    ArpFrame ah;        // ARP帧
};

// 发送的参数结构
struct SendParam {
    pcap_t* adhandle;
    char* ip;
    u_char* mac;
    char* netmask;
};

// 接收的参数结构
struct GetParam {
    pcap_t* adhandle;
};

// IP地址格式(用于输出)
struct IpAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    IpAddress() = default;
    IpAddress(const struct in_addr& t) {
         byte1 = t.S_un.S_un_b.s_b1;
         byte2 = t.S_un.S_un_b.s_b2;
         byte3 = t.S_un.S_un_b.s_b3;
         byte4 = t.S_un.S_un_b.s_b4;
    }
    operator in_addr() const {
        struct in_addr t;
        t.S_un.S_un_b.s_b1 = byte1;
        t.S_un.S_un_b.s_b2 = byte2;
        t.S_un.S_un_b.s_b3 = byte3;
        t.S_un.S_un_b.s_b4 = byte4;
        return t;
    }
};

// IP头部结构体（20B）
struct IpHeader {
#define IP_HDR_LEN 28
    u_char version_hlen;               // 版本信息4位+头长度4位 1字节
    u_char ip_tos;                     // 服务类型    1字节
    u_short ip_length;                   // 数据包长度 2字节
    u_short ip_id;                       // 数据包标识  2字节
    u_short ip_flag_off;                 // 标志3位，片偏移13位  2字节
    u_char ip_ttl;                     // 存活时间  1字节
    u_char ip_protocol;                // 协议类型  1字节
    u_short ip_checksum;                 // 首部校验和 2字节
    struct IpAddress ip_souce_address;   // 源IP地址   4字节
    struct IpAddress ip_destination_address;  // 目的IP地址  4字节
};

// TCP头部结构体（20B）
struct TcpHeader {
#define TCP_HDR_LEN 20
    u_short src_port;           // 源端口号  2字节
    u_short dest_port;           // 目的端口号 2字节
    u_int sequence_num;         // 序号  4字节
    u_int acknowledgment;      // 确认号  4字节
    u_char hdr_len;             // 首部长度4位+保留位6位 共10位
    u_char flags;              // 标志位6位
    u_short advertised_window;  // 窗口大小16位 2字节
    u_short check_sum;          // 校验和16位   2字节
    u_short urg_ptr;            // 紧急指针16位   2字节
};

// TCP伪首部结构体（12B）
struct PsdTcpHeader {
#define PSDTCP_HDR_LEN 12
    struct IpAddress src_addr;       // 源IP地址  4字节
    struct IpAddress des_addr;  // 目的IP地址 4字节
    char zero;                       // 填充位  1字节
    char protcol;                    // 协议号  1字节
    u_short tcp_len;                  // TCP包长度 2字节
};

// IPv4点分十进制格式(适用于输入)
struct IPv4 {
    u_short ip1, ip2, ip3, ip4;
};
#pragma pack() // 取消按一个字节内存对齐