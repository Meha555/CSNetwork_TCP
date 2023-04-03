#pragma once
#include <pcap.h>
#include <inaddr.h>
#pragma pack(1)     // 按一个字节内存对齐
// 以太网帧头部结构体（14B）
struct EthernetHeader {
#define EN_HDR_LEN 14
    u_char DestMAC[6];  // 目的MAC地址 6字节
    u_char SourMAC[6];  // 源MAC地址 6字节
    u_short EthType;    // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

// ARP帧结构（28B）
struct ArpFrame {
#define ARP_FRME_LEN 28
    u_short HardwareType;     // 硬件类型
    u_short ProtocolType;     // 协议类型
    u_char HardwareAddrLen;   // 硬件地址长度
    u_char ProtocolAddrLen;   // 协议地址长度
    u_short OperationField;   // 操作字段
    u_char SourceMacAddr[6];  // 源mac地址
    u_long SourceIpAddr;      // 源ip地址
    u_char DestMacAddr[6];    // 目的mac地址
    u_long DestIpAddr;        // 目的ip地址
};

// arp包结构
struct ArpPacket {
#define ARP_PKT_LEN 42
    EthernetHeader ed;  // 以太网首部
    ArpFrame ah;        // ARP帧
};

// 发送的参数结构
struct sparam {
    pcap_t* adhandle;
    char* ip;
    u_char* mac;
    char* netmask;
};

// 接收的参数结构
struct gparam {
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
    u_char Version_HLen;               // 版本信息4位+头长度4位 1字节
    u_char ip_tos;                     // 服务类型    1字节
    short ip_length;                   // 数据包长度 2字节
    short ip_id;                       // 数据包标识  2字节
    short ip_flag_off;                 // 标志3位，片偏移13位  2字节
    u_char ip_ttl;                     // 存活时间  1字节
    u_char ip_protocol;                // 协议类型  1字节
    short ip_checksum;                 // 首部校验和 2字节
    struct IpAddress ip_souce_address;   // 源IP地址   4字节
    struct IpAddress ip_destination_address;  // 目的IP地址  4字节
};

// TCP头部结构体（20B）
struct TcpHeader {
#define TCP_HDR_LEN 20
    u_short SrcPort;           // 源端口号  2字节
    u_short DstPort;           // 目的端口号 2字节
    u_int SequenceNum;         // 序号  4字节
    u_int Acknowledgment;      // 确认号  4字节
    u_char HdrLen;             // 首部长度4位+保留位6位 共10位
    u_char Flags;              // 标志位6位
    u_short AdvertisedWindow;  // 窗口大小16位 2字节
    u_short Checksum;          // 校验和16位   2字节
    u_short UrgPtr;            // 紧急指针16位   2字节
};

// TCP伪首部结构体（12B）
struct PsdTcpHeader {
#define PSDTCP_HDR_LEN 12
    struct IpAddress SourceAddr;       // 源IP地址  4字节
    struct IpAddress DestinationAddr;  // 目的IP地址 4字节
    char Zero;                       // 填充位  1字节
    char Protcol;                    // 协议号  1字节
    u_short TcpLen;                  // TCP包长度 2字节
};

// IPv4点分十进制格式(适用于输入)
struct IPv4 {
    u_short ip1, ip2, ip3, ip4;
};
#pragma pack() // 取消按一个字节内存对齐