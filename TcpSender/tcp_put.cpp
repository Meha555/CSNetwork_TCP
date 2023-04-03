﻿#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#define MAX_STR_SIZE 500
#define ETH_ARP 0x0806                                                         // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE 1                                                         // 硬件类型字段值为表示以太网地址
#define ETH_IP 0x0800                                                          // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST 1                                                          // ARP请求
#define ARP_REPLY 2                                                            // ARP应答
#define HOSTNUM 255                                                            // 主机数量
char* iptos(u_long in);                                                        // u_long即为 unsigned long
void ifget(pcap_if_t* d, char* ip_addr, char* ip_netmask);                     // 用ifget方法获取自身的IP和子网掩码
int GetSelfMac(pcap_t* adhandle, const char* ip_addr, unsigned char* ip_mac);  // 发送一个ARP请求来获取自身的MAC地址
unsigned short checksum(unsigned short* data, int length);                     // 校验和方法
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
bool flag;
// 声明两个线程
HANDLE sendthread;  // 发送ARP包线程
HANDLE recvthread;  // 接受ARP包线程
#pragma pack(1)     // 按一个字节内存对齐
// 帧头部结构体，共14字节
struct EthernetHeader {
    u_char DestMAC[6];  // 目的MAC地址 6字节
    u_char SourMAC[6];  // 源MAC地址 6字节
    u_short EthType;    // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

// 28字节ARP帧结构
struct Arpheader {
    unsigned short HardwareType;    // 硬件类型
    unsigned short ProtocolType;    // 协议类型
    unsigned char HardwareAddLen;   // 硬件地址长度
    unsigned char ProtocolAddLen;   // 协议地址长度
    unsigned short OperationField;  // 操作字段
    unsigned char SourceMacAdd[6];  // 源mac地址
    unsigned long SourceIpAdd;      // 源ip地址
    unsigned char DestMacAdd[6];    // 目的mac地址
    unsigned long DestIpAdd;        // 目的ip地址
};

// arp包结构
struct ArpPacket {
    EthernetHeader ed;
    Arpheader ah;
};

struct sparam {
    pcap_t* adhandle;
    char* ip;
    unsigned char* mac;
    char* netmask;
};
struct gparam {
    pcap_t* adhandle;
};

// IP地址格式
struct IpAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

// IP头部结构体，共20字节
struct IpHeader {
    unsigned char Version_HLen;  // 版本信息4位 ，头长度4位 1字节
    unsigned char TOS;           // 服务类型    1字节
    short Length;                // 数据包长度 2字节
    short Ident;                 // 数据包标识  2字节
    short Flags_Offset;          // 标志3位，片偏移13位  2字节
    unsigned char TTL;           // 存活时间  1字节
    unsigned char Protocol;      // 协议类型  1字节
    short Checksum;              // 首部校验和 2字节
    IpAddress SourceAddr;        // 源IP地址   4字节
    IpAddress DestinationAddr;   // 目的IP地址  4字节
};

// TCP头部结构体，共20字节
struct TcpHeader {
    unsigned short SrcPort;           // 源端口号  2字节
    unsigned short DstPort;           // 目的端口号 2字节
    unsigned int SequenceNum;         // 序号  4字节
    unsigned int Acknowledgment;      // 确认号  4字节
    unsigned char HdrLen;             // 首部长度4位，保留位6位 共10位
    unsigned char Flags;              // 标志位6位
    unsigned short AdvertisedWindow;  // 窗口大小16位 2字节
    unsigned short Checksum;          // 校验和16位   2字节
    unsigned short UrgPtr;            // 紧急指针16位   2字节
};

// TCP伪首部结构体 12字节
struct PsdTcpHeader {
    IpAddress SourceAddr;       // 源IP地址  4字节
    IpAddress DestinationAddr;  // 目的IP地址 4字节
    char Zero;                  // 填充位  1字节
    char Protcol;               // 协议号  1字节
    unsigned short TcpLen;      // TCP包长度 2字节
};

struct sparam sp;
struct gparam gp;

int main() {
    char* ip_addr;          // IP地址
    char* ip_netmask;       // 子网掩码
    unsigned char* ip_mac;  // 本机MAC地址
    /* 为这三个变量分配地址空间*/
    ip_addr = (char*)malloc(sizeof(char) * 16);  // 申请内存存放IP地址
    if (ip_addr == NULL) {
        printf("申请内存存放IP地址失败!\n");
        return -1;
    }
    ip_netmask = (char*)malloc(sizeof(char) * 16);  // 申请内存存放NETMASK地址
    if (ip_netmask == NULL) {
        printf("申请内存存放NETMASK地址失败!\n");
        return -1;
    }
    ip_mac = (unsigned char*)malloc(sizeof(unsigned char) * 6);  // 申请内存存放MAC地址
    if (ip_mac == NULL) {
        printf("申请内存存放MAC地址失败!\n");
        return -1;
    }
    pcap_if_t* alldevs;             // 所有网络适配器
    pcap_if_t* d;                   // 选中的网络适配器
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区,大小为256
    pcap_t* adhandle;               // 捕捉实例,是pcap_open返回的对象
    int i = 0;                      // 适配器计数变量
    /* 获取适配器列表并选中相应的适配器,*/
    // 获取本地适配器列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        // 结果为-1代表出现获取适配器列表失败
        fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
        // exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统
        exit(1);
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n", ++i, d->name);
        if (d->description) {
            // 打印适配器的描述信息
            printf("description:%s\n", d->description);
        } else {
            // 适配器不存在描述信息
            printf("description:%s", "no description\n");
        }
        // 打印本地环回地址
        printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
        /**
        pcap_addr *  next     指向下一个地址的指针
        sockaddr *  addr       IP地址
        sockaddr *  netmask  子网掩码
        sockaddr *  broadaddr   广播地址
        sockaddr *  dstaddr        目的地址
        */
        pcap_addr_t* a;  // 网络适配器的地址用来存储变量
        for (a = d->addresses; a; a = a->next) {
            // sa_family代表了地址的类型,是IPV4地址类型还是IPV6地址类型
            switch (a->addr->sa_family) {
                case AF_INET:  // 代表IPV4类型地址
                    printf("Address Family Name:AF_INET\n");
                    if (a->addr) {
                        //->的优先级等同于括号,高于强制类型转换,因为addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型
                        printf("Address:%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                    }
                    if (a->netmask) {
                        printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                    }
                    if (a->broadaddr) {
                        printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                    }
                    if (a->dstaddr) {
                        printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                    }
                    break;
                case AF_INET6:  // 代表IPV6类型地址
                    printf("Address Family Name:AF_INET6\n");
                    printf("this is an IPV6 address\n");
                    break;
                default:
                    break;
            }
        }
    }
    // i为0代表上述循环未进入,即没有找到适配器,可能的原因为Winpcap没有安装导致未扫描到
    if (i == 0) {
        printf("interface not found,please check winpcap installation");
    }

    int num;
    printf("Enter the interface number(1-%d):", i);
    // 让用户选择选择哪个适配器进行抓包
    scanf("%d", &num);
    printf("\n");

    // 用户输入的数字超出合理范围
    if (num < 1 || num > i) {
        printf("number out of range\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    // 跳转到选中的适配器
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++)
        ;

    // 运行到此处说明用户的输入是合法的
    if ((adhandle = pcap_open(d->name,                    // 设备名称
                              65535,                      // 存放数据包的内容长度
                              PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                              1000,                       // 超时时间
                              NULL,                       // 远程验证
                              errbuf                      // 错误缓冲
                              )) == NULL) {
        // 打开适配器失败,打印错误并释放适配器列表
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }
    /*对sp和gp两个ARP请求所需要的结构体进行赋值 */
    ifget(d, ip_addr, ip_netmask);  // 获取所选网卡的基本信息--掩码--IP地址

    GetSelfMac(adhandle, ip_addr, ip_mac);

    sp.adhandle = adhandle;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle;
    /*直接创建两个线程，一个是发送一个接受，分别调用两个方法*/
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket,
                              &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetLivePC, &gp,
                              0, NULL);
    printf("\nlistening on 网卡%d ...\n", i);
    pcap_freealldevs(alldevs);
    getchar();
    getchar();

    while (true) {
        char* TcpData;                               // 发送内容
        TcpData = (char*)malloc(sizeof(char) * 50);  // 申请内存存放NETMASK地址
        if (TcpData == NULL) {
            printf("申请内存存放NETMASK地址失败!\n");
            return -1;
        }
        struct EthernetHeader ethernet;  // 以太网帧头
        struct IpHeader ip;              // IP头
        struct TcpHeader tcp;            // TCP头
        struct PsdTcpHeader ptcp;        // TCP伪首部
        unsigned char SendBuffer[500];   // 发送队列
        u_int ip1, ip2, ip3, ip4;
        scanf("%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
        printf("请输入你要发送的内容:\n");
        getchar();
        std::cin.getline(TcpData, MAX_STR_SIZE);
        //gets(TcpData);
        printf("要发送的内容:%s\n", TcpData);

        // 结构体初始化为0序列
        memset(&ethernet, 0, sizeof(ethernet));
        BYTE destmac[8];
        // 目的MAC地址,此处没有对帧的MAC地址进行赋值，因为网卡设置的混杂模式，可以接受经过该网卡的所有帧。
        // 当然最好的方法是赋值为ARP刚才获取到的MAC地址，当然不赋值也可以捕捉到并解析。
        destmac[0] = 0x00;
        destmac[1] = 0x11;
        destmac[2] = 0x22;
        destmac[3] = 0x33;
        destmac[4] = 0x44;
        destmac[5] = 0x55;
        // 赋值目的MAC地址
        memcpy(ethernet.DestMAC, destmac, 6);
        BYTE hostmac[8];
        // 源MAC地址
        hostmac[0] = 0x00;
        hostmac[1] = 0x1a;
        hostmac[2] = 0x4d;
        hostmac[3] = 0x70;
        hostmac[4] = 0xa3;
        hostmac[5] = 0x89;
        // 赋值源MAC地址
        memcpy(ethernet.SourMAC, hostmac, 6);
        // 上层协议类型,0x0800代表IP协议
        ethernet.EthType = htons(0x0800);
        // 赋值SendBuffer
        memcpy(&SendBuffer, &ethernet, sizeof(struct EthernetHeader));
        // 赋值IP头部信息
        ip.Version_HLen = 0x45;
        ip.TOS = 0;
        ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
        ip.Ident = htons(1);
        ip.Flags_Offset = 0;
        ip.TTL = 128;
        ip.Protocol = 6;
        ip.Checksum = 0;
        // 源IP地址
        ip.SourceAddr.byte1 = 127;
        ip.SourceAddr.byte2 = 0;
        ip.SourceAddr.byte3 = 0;
        ip.SourceAddr.byte4 = 1;
        // 目的IP地址
        ip.DestinationAddr.byte1 = ip1;
        ip.DestinationAddr.byte2 = ip2;
        ip.DestinationAddr.byte3 = ip3;
        ip.DestinationAddr.byte4 = ip4;
        // 赋值SendBuffer
        memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &ip, 20);
        // 赋值TCP头部内容
        tcp.DstPort = htons(102);
        tcp.SrcPort = htons(1000);
        tcp.SequenceNum = htonl(11);
        tcp.Acknowledgment = 0;
        tcp.HdrLen = 0x50;
        tcp.Flags = 0x18;
        tcp.AdvertisedWindow = htons(512);
        tcp.UrgPtr = 0;
        tcp.Checksum = 0;
        // 赋值SendBuffer
        memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
        // 赋值伪首部
        ptcp.SourceAddr = ip.SourceAddr;
        ptcp.DestinationAddr = ip.DestinationAddr;
        ptcp.Zero = 0;
        ptcp.Protcol = 6;
        ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
        // 声明临时存储变量，用来计算校验和
        char TempBuffer[65535];
        memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
        memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
        memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
        // 计算TCP的校验和
        tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
        // 重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
        memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
        memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
        // 初始化TempBuffer为0序列，存储变量来计算IP校验和
        memset(TempBuffer, 0, sizeof(TempBuffer));
        memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
        // 计算IP校验和
        ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
        // 重新把SendBuffer赋值，IP校验和已经改变
        memcpy(SendBuffer + sizeof(struct EthernetHeader), &ip, sizeof(struct IpHeader));
        // 发送序列的长度
        int size = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData);
        int result = pcap_sendpacket(adhandle, SendBuffer, size);
        /*if (result != 0) {
            printf("Send Error!\n");
        } else {*/
            printf("发送TCP数据包.\n");
            printf("目的端口:%d\n", ntohs(tcp.DstPort));
            printf("源端口:%d\n", ntohs(tcp.SrcPort));
            printf("序号:%d\n", ntohl(tcp.SequenceNum));
            printf("确认号:%d\n", ntohl(tcp.Acknowledgment));
            printf("首部长度:%d*4\n", tcp.HdrLen >> 4);
            printf("标志位:0x%0x\n", ntohs(tcp.Flags));
            printf("窗口大小:%d\n", ntohs(tcp.AdvertisedWindow));
            printf("紧急指针:%d\n", ntohs(tcp.UrgPtr));
            printf("检验和:%u\n", ntohs(tcp.Checksum));
            printf("发送成功!\n");
        //}
        free(TcpData);
    }
    return 0;
}
/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS 12
char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;

    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
// 获取IP和子网掩码赋值为ip_addr和ip_netmask
void ifget(pcap_if_t* d, char* ip_addr, char* ip_netmask) {
    pcap_addr_t* a;
    // 遍历所有的地址,a代表一个pcap_addr
    for (a = d->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {
            case AF_INET:  // sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
                if (a->addr) {
                    char* ipstr;
                    // 将地址转化为字符串
                    ipstr = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);  //*ip_addr
                    printf("ipstr:%s\n", ipstr);
                    memcpy(ip_addr, ipstr, 16);  // memcpy 函数用于 把资源内存（src所指向的内存区域） 拷贝到目标内存（dest所指向的内存区域）；
                                                 // 拷贝多少个？有一个size变量控制拷贝的字节数；
                }
                if (a->netmask) {
                    char* netmaskstr;
                    netmaskstr = iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);
                    printf("netmask:%s\n", netmaskstr);
                    memcpy(ip_netmask, netmaskstr, 16);
                }
            case AF_INET6:
                break;
        }
    }
}

// 获取本机的MAC地址
int GetSelfMac(pcap_t* adhandle, const char* ip_addr, u_char* ip_mac) {
    u_char sendbuf[42];  // arp包结构大小 arp报文总共42 bytes。其中以太网首部14bytes，arp字段28字节
    int i = -1;
    int res;
    EthernetHeader eh;  // 以太网帧头
    Arpheader ah;       // ARP帧头
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    memset(eh.DestMAC, 0xff, 6);  // 目的地址为全1为广播地址
    memset(eh.SourMAC, 0x0f, 6);  // 以太网源地址
    // htons将一个无符号短整型的主机数值转换为网络字节顺序
    eh.EthType = htons(ETH_ARP);
    ah.HardwareType = htons(ARP_HARDWARE);
    ah.ProtocolType = htons(ETH_IP);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.OperationField = htons(ARP_REQUEST);
    memset(ah.SourceMacAdd, 0x00, 6);//发送者MAC地址
    ah.SourceIpAdd = inet_addr("100.100.100.100");  // 随便设的请求方ip
    memset(ah.DestMacAdd, 0x0f, 6);  //目的MAC地址
    ah.DestIpAdd = inet_addr(ip_addr);

    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    printf("发送的ARP广播分组：%s", sendbuf);

    pcap_sendpacket(adhandle, sendbuf, 42);
    /*if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
        printf("\nPacketSend succeed\n");
    } else {
        printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        return 0;
    }*/
    // 从interface或离线记录文件获取一个报文
    while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
        printf("ETH_ARP = %hd, %hd\n", *(u_short*)(pkt_data + 12), htons(ETH_ARP));
        printf("ARP_REPLY = %hd, %hd\n", *(u_short*)(pkt_data + 20), htons(ARP_REPLY));
        printf("ARP请求方IP = %s, %s\n", iptos(*(u_long*)(pkt_data + 38)), "100.100.100.100");
        if (*(u_short*)(pkt_data + 12) == htons(ETH_ARP) && *(u_short*)(pkt_data + 20) == htons(ARP_REPLY) && *(u_long*)(pkt_data + 38) == inet_addr("100.100.100.100")) {
            for (i = 0; i < 6; i++) {
                ip_mac[i] = *(u_char*)(pkt_data + 22 + i);
            }
            printf("获取本机MAC地址成功!\n");
            break;
        }
    }
    if (i == 6)
        return 1;
    else
        return 0;
}


//// 获取自己主机的MAC地址【原配】
//int GetSelfMac(pcap_t* adhandle, const char* ip_addr, unsigned char* ip_mac) {
//    unsigned char sendbuf[42];  // arp包结构大小
//    int i = -1;
//    int res;
//    EthernetHeader eh;  // 以太网帧头
//    Arpheader ah;       // ARP帧头
//    struct pcap_pkthdr* pkt_header;
//    const u_char* pkt_data;
//    // 将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
//    memset(eh.DestMAC, 0xff, 6);  // 目的地址为全为广播地址
//    memset(eh.SourMAC, 0x0f, 6);
//    memset(ah.DestMacAdd, 0x0f, 6);
//    memset(ah.SourceMacAdd, 0x00, 6);
//    // htons将一个无符号短整型的主机数值转换为网络字节顺序
//    eh.EthType = htons(ETH_ARP);
//    ah.HardwareType = htons(ARP_HARDWARE);
//    ah.ProtocolType = htons(ETH_IP);
//    ah.HardwareAddLen = 6;
//    ah.ProtocolAddLen = 4;
//    ah.SourceIpAdd = inet_addr("100.100.100.100");  // 随便设的请求方ip 192.168.43.208
//    ah.OperationField = htons(ARP_REQUEST);
//    ah.DestIpAdd = inet_addr(ip_addr);
//
//    memset(sendbuf, 0, sizeof(sendbuf));
//    memcpy(sendbuf, &eh, sizeof(eh));
//    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
//    printf("%s", sendbuf);
//
//    pcap_sendpacket(adhandle, sendbuf, 42);
//    /*if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
//        printf("\nPacketSend succeed\n");
//    } else {
//        printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
//        return 0;
//    }*/
//    // 从interface或离线记录文件获取一个报文
//    while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
//        if (*(unsigned short*)(pkt_data + 12) == htons(ETH_ARP) && *(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY) && *(unsigned long*)(pkt_data + 38) == inet_addr("100.100.100.100")) {
//            printf("ETH_ARP = %hd, %hd\n", *(u_short*)(pkt_data + 12), htons(ETH_ARP));
//            printf("ARP_REPLY = %hd, %hd\n", *(u_short*)(pkt_data + 20), htons(ARP_REPLY));
//            printf("ARP Sender IP = %s, %hd\n", iptos(*(u_long*)(pkt_data + 38)), inet_addr("100.100.100.100"));
//            for (i = 0; i < 6; i++) {
//                ip_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
//            }
//            printf("获取自己主机的MAC地址成功!\n");
//            break;
//        }
//    }
//    if (i == 6) {
//        return 1;
//    } else {
//        return 0;
//    }
//}

/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
DWORD WINAPI SendArpPacket(LPVOID lpParameter)  //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
    sparam* spara = (sparam*)lpParameter;
    pcap_t* adhandle = spara->adhandle;
    char* ip = spara->ip;
    unsigned char* mac = spara->mac;
    char* netmask = spara->netmask;
    printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
    printf("自身的IP地址为:%s\n", ip);
    printf("地址掩码NETMASK为:%s\n", netmask);
    printf("\n");
    unsigned char sendbuf[42];  // arp包结构大小
    EthernetHeader eh;
    Arpheader ah;
    // 赋值MAC地址
    memset(eh.DestMAC, 0xff, 6);  // 目的地址为全为广播地址
    memcpy(eh.SourMAC, mac, 6);
    memcpy(ah.SourceMacAdd, mac, 6);
    memset(ah.DestMacAdd, 0x00, 6);
    eh.EthType = htons(ETH_ARP);
    ah.HardwareType = htons(ARP_HARDWARE);
    ah.ProtocolType = htons(ETH_IP);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.SourceIpAdd = inet_addr(ip);  // 请求方的IP地址为自身的IP地址
    ah.OperationField = htons(ARP_REQUEST);
    // 向局域网内广播发送arp包
    unsigned long myip = inet_addr(ip);
    unsigned long mynetmask = inet_addr(netmask);
    unsigned long hisip = htonl((myip & mynetmask));
    // 向255个主机发送
    for (int i = 0; i < HOSTNUM; i++) {
        ah.DestIpAdd = htonl(hisip + i);
        // 构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        // 如果发送成功
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
            //	printf("\nPacketSend succeed1\n");
        } else {
            printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        }
        Sleep(50);
    }
    Sleep(1000);
    flag = TRUE;
    return 0;
}
/* 分析截留的数据包获取活动的主机IP地址 */
DWORD WINAPI GetLivePC(LPVOID lpParameter)  //(pcap_t *adhandle)
{
    gparam* gpara = (gparam*)lpParameter;
    pcap_t* adhandle = gpara->adhandle;
    int res;
    unsigned char Mac[6];
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    while (true) {
        if (flag) {
            printf("获取MAC地址完毕,请输入你要发送对方的IP地址:\n");
            break;
        }
        if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
            if (*(unsigned short*)(pkt_data + 12) == htons(ETH_ARP)) {
                ArpPacket* recv = (ArpPacket*)pkt_data;
                if (*(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY)) {
                    printf("-------------------------------------------\n");
                    printf("IP地址:%d.%d.%d.%d   MAC地址:",
                           recv->ah.SourceIpAdd & 255,
                           recv->ah.SourceIpAdd >> 8 & 255,
                           recv->ah.SourceIpAdd >> 16 & 255,
                           recv->ah.SourceIpAdd >> 24 & 255);
                    for (int i = 0; i < 6; i++) {
                        Mac[i] = *(unsigned char*)(pkt_data + 22 + i);
                        printf("%02x", Mac[i]);
                    }
                    printf("\n");
                }
            }
        }
        Sleep(10);
    }
    return 0;
}
// 获得校验和的方法
unsigned short checksum(unsigned short* data, int length) {
    unsigned long temp = 0;
    while (length > 1) {
        temp += *data++;
        length -= sizeof(unsigned short);
    }
    if (length) {
        temp += *(unsigned short*)data;
    }
    temp = (temp >> 16) + (temp & 0xffff);
    temp += (temp >> 16);
    return (unsigned short)(~temp);
}
