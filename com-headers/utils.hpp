#pragma once
#include <time.h>
#include "net-types.h"

#define MEMCPY(dest, src, type) memcpy(dest, src, sizeof(type));
#define MEMSET(dest, data, type) memset(dest, data, sizeof(type));
#define ALLOCATE(type, num) (type*)malloc(sizeof(type) * num);

#define MAX_STR_SIZE 500  // 从控制台允许的最大输入长度
#define MTU_SIZE 65535    // 最大传输单元长度
#define TIME_OUT 1000     // 超时时间

#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86DD
#define ETH_ARP 0x0806
#define ETH_RARP 0x0835

#define ARP_HARDWARE 1
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMPV4 1
#define IP_ICMPV6 58
// 硬件类型字段值为表示以太网地址                                         // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define IPTOSBUFFERS 12

/* 将数字类型的IPv4地址转换成字符串 */
char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;
    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/* 将数字类型的IPv6地址转换成字符串 */
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen) {
    socklen_t sockaddrlen;
#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif
    if (getnameinfo(sockaddr,
                    sockaddrlen,
                    address,
                    addrlen,
                    NULL,
                    0,
                    NI_NUMERICHOST) != 0)
        address = NULL;
    return address;
}

// 获得校验和
u_short checksum(u_short* data, int length) {
    u_long temp = 0;
    while (length > 1) {
        temp += *data++;
        length -= sizeof(u_short);
    }
    if (length) {
        temp += *(u_short*)data;
    }
    temp = (temp >> 16) + (temp & 0xffff);
    temp += (temp >> 16);
    return (u_short)(~temp);
}

// 打印设备信息
void ifprint(pcap_if_t* dev, int& i) {
    printf("-----------------------------------------------------------------\n序号: %d\n名称: %s\n", ++i, dev->name);
    if (dev->description) {
        // 打印适配器的描述信息
        printf("适配器描述:%s\n", dev->description);
    } else {
        // 适配器不存在描述信息
        printf("适配器描述:%s", "无可用描述信息\n");
    }
    // 打印本地环回地址
    printf("\t环回地址: %s\n", (dev->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
    pcap_addr_t* a;  // 网络适配器IP地址
    for (a = dev->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {  // sa_family代表了地址的类型（IPV4地址类型/IPV6地址）
            case AF_INET:              // 代表IPV4类型地址
                printf("IP地址类型:IPv4\n");
                if (a->addr) {
                    printf("IPv4地址:%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                }
                if (a->netmask) {
                    printf("\t子网掩码: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                }
                if (a->broadaddr) {
                    printf("\t广播地址: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                }
                if (a->dstaddr) {
                    printf("\t目的地址: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                }
                break;
            case AF_INET6:  // 代表IPV6类型地址
                printf("IP地址类型:IPv6\n");
                if (a->addr) {
                    char ip6str[128];
                    printf("IPv6地址: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                }
                break;
            default:
                printf("\t未知的IP地址类型\n");
                break;
        }
    }
}

/* 向本网路内所有可能的主机发送ARP帧 */
DWORD WINAPI thread_send_arp(LPVOID lpParameter) {
    SendParam* spara = (SendParam*)lpParameter;
    pcap_t* adhandle = spara->adhandle;
    char* ip = spara->ip;
    u_char* mac = spara->mac;
    char* netmask = spara->netmask;
    printf("本机MAC地址：%02X-%02X-%02X-%02X-%02X-%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("本机IP地址：%s\n", ip);
    printf("子网掩码NETMASK为：%s\n", netmask);
    printf("\n");
    u_char sendbuf[42];  // arp包结构大小
    ethernet_header eh;
    arp_header ah;

    // ANCHOR - 赋值MAC地址
    memset(&(eh.des_mac_addr), 0xff, 6);  // 以太网帧目的MAC地址为全1为广播地址
    memcpy(&(eh.src_mac_addr), mac, 6);   // 以太网帧源MAC地址
    eh.type = htons(ETH_ARP);

    memcpy(&(ah.src_mac_addr), mac, 6);   // ARP帧源MAC地址
    memset(&(ah.des_mac_addr), 0x00, 6);  // ARP帧目的MAC地址
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IPV4);
    ah.hardware_length = 6;
    ah.protocol_length = 4;
    ah.src_ip_addr.bin_fmt = inet_addr(ip);  // 请求方的IP地址为自身的IP地址
    ah.operation_code = htons(ARP_REQUEST);

    printf("=========================发送/接收Arp帧==========================\n");
    printf("向本网路内所有可能的主机发送ARP请求包\n");

    // 向局域网内广播发送arp帧
    u_long my_ip = inet_addr(ip);
    u_long my_netmask = inet_addr(netmask);
    u_long unknown_ip = htonl((my_ip & my_netmask));
    // 向网络前缀为24位的CIDR地址块中的255个主机发送ARP请求帧
    for (int i = 0; i < 255; i++) {
        ah.des_ip_addr.bin_fmt = htonl(unknown_ip + i);
        // 构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));

        pcap_sendpacket(adhandle, sendbuf, ARP_PKT_LEN);  // 发送填入自己MAC地址的ARP报文
        //  如果发送成功
        /*if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
                printf("\n成功发送ARP请求分组\n");
        } else {
                printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        }*/
        Sleep(50);
    }
    Sleep(1000);
    flag = true;
    return 0;
}

extern bool flag;
/* 获取活动的主机IP地址 */
DWORD WINAPI thread_live_ip(LPVOID lpParameter) {
    GetParam* gpara = (GetParam*)lpParameter;
    pcap_t* adhandle = gpara->adhandle;
    u_char mac[6];
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    printf("分析截留的数据包获取活动的主机IP地址\n");
    while (true) {
        if (flag) {
            printf("=========================填写数据包信息==========================\n");
            printf("获取MAC地址完毕,请输入你要发送对方的IP地址:\n");
            break;
        }
        if ((pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
            if (*(u_short*)(pkt_data + 12) == htons(ETH_ARP)) {  // 如果捕获的是ARP帧
                arp_packet* recv = (arp_packet*)pkt_data;
                if (*(u_short*)(pkt_data + 20) == htons(ARP_REPLY)) {
                    printf("------------------------------------------------\n");
                    printf("IP地址:%d.%d.%d.%d   MAC地址:",
                           recv->ah.src_ip_addr.bin_fmt & 255,
                           recv->ah.src_ip_addr.bin_fmt >> 8 & 255,
                           recv->ah.src_ip_addr.bin_fmt >> 16 & 255,
                           recv->ah.src_ip_addr.bin_fmt >> 24 & 255);
                    for (int i = 0; i < 6; i++) {
                        if (0 < i && i < 6)
                            printf("-");
                        mac[i] = *(u_char*)(pkt_data + 22 + i);
                        printf("%02X", mac[i]);
                    }
                    printf("\n");
                }
            }
        }
        Sleep(10);
    }
    return 0;
}

// 获取本机所有网卡的IP和子网掩码并赋值为ip_addr和ip_netmask
void getIP(pcap_if_t* d, char* ip_addr, char* ip_netmask) {
    pcap_addr_t* a;
    // 遍历所有的地址,a代表一个pcap_addr
    for (a = d->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {
            case AF_INET:  // sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
                if (a->addr) {
                    char* ipstr;
                    // 将地址转化为字符串
                    ipstr = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);  //*ip_addr
                    printf("IPv4地址:%s\n", ipstr);
                    memcpy(ip_addr, ipstr, 16);
                }
                if (a->netmask) {
                    char* netmaskstr;
                    netmaskstr = iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);
                    printf("子网掩码:%s\n", netmaskstr);
                    memcpy(ip_netmask, netmaskstr, 16);
                }
            case AF_INET6:
                char ip6str[128];
                printf("IPv6地址: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                break;
        }
    }
}

// 获取当前网卡的MAC地址（本网卡发送，本网卡接收）
int getSelfMAC(pcap_t* adhandle, const char* ip_addr, u_char* ip_mac) {
    u_char sendbuf[ARP_PKT_LEN];  // arp包结构：总共42 bytes。其中以太网首部14bytes，arp字段28字节
    ethernet_header eh;           // 以太网帧头
    arp_header ah;                // ARP帧头
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    int i = -1;
    int res;
    /* ------------------------------ 制作一个伪造的ARP请求帧 ----------------------------- */
    memset(&(eh.des_mac_addr), 0xff, 6);  // 以太网帧目的MAC地址为全1为广播地址
    memset(&(eh.src_mac_addr), 0x0f, 6);  // 以太网帧源MAC地址(无需和发送者回信，所以随便填)
    eh.type = htons(ETH_ARP);

    memset(&(ah.src_mac_addr), 0x00, 6);  // ARP帧源MAC地址(无需和发送者回信，所以随便填)
    memset(&(ah.des_mac_addr), 0x0f, 6);  // ARP帧目的MAC地址(无需和发送者回信，所以随便填)
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IPV4);
    ah.hardware_length = 6;
    ah.protocol_length = 4;
    char* fake_ip = "100.100.100.100";
    ah.src_ip_addr.bin_fmt = inet_addr(fake_ip);  // 随便设的请求方ip(无需和发送者回信，所以随便填)
    ah.operation_code = htons(ARP_REQUEST);
    ah.des_ip_addr.bin_fmt = inet_addr(ip_addr);  // ARP帧目的IP需要填真的，因为靠这个字段来收下ARP帧

    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    printf("发送的ARP广播分组：%s", sendbuf);

    /* ------------------------------ 发送这个伪造的ARP请求 ------------------------------ */
    pcap_sendpacket(adhandle, sendbuf, ARP_PKT_LEN);
    /*if (pcap_sendpacket(adhandle, sendbuf, ARP_PKT_LEN) == 0) {
            printf("\n成功发送ARP广播分组\n");
    }
    else {
            printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
            return 0;
    }*/

    /* ------------------ 当前网卡会对上面伪造的ARP请求做出响应，这里获取并分析这个ARP响应帧 ------------------ */
    while (pcap_next_ex(adhandle, &pkt_header, &pkt_data) >= 0) {
        printf("ETH_ARP = %hd\n", ntohs(*(u_short*)(pkt_data + 12)));
        printf("ARP_REPLY = %hd\n", ntohs(*(u_short*)(pkt_data + 20)));
        printf("ARP请求方IP = %s\n", iptos(*(u_long*)(pkt_data + 38)));
        arp_header* ah = (arp_header*)(pkt_data + 12);
        /*if (ah->hardware_type == htons(ETH_ARP) && ah->protocol_type == htons(ARP_REPLY) && ah->des_ip_addr.bin_fmt == inet_addr(fake_ip)) {
                memcpy(ip_mac, &(ah->src_mac_addr), 6);
                printf("获取本机MAC地址成功!\n");
                break;
        }*/
        // 如果是ARP帧且是ARP请求帧且目的IP是约定的
        if (*(u_short*)(pkt_data + 12) == htons(ETH_ARP) && *(u_short*)(pkt_data + 20) == htons(ARP_REPLY) && *(u_long*)(pkt_data + 38) == inet_addr(fake_ip)) {
            for (i = 0; i < 6; i++) {
                ip_mac[i] = *(u_char*)(pkt_data + 22 + i);
            }
            printf("获取本机MAC地址成功!\n");
            break;
        }
    }
    return i == 6;
}

/* -------------------------------------------------------------------------- */
/*                                    发送                                    */
/* -------------------------------------------------------------------------- */
#define DEST_PORT 102  // 目的端口号
#define SRC_PORT 1000  // 源端口号
#define SEQ_NUM 11
#define ACK_NUM 0

// 发送的参数
struct SendParam {
    pcap_t* adhandle;
    char* ip;
    u_char* mac;
    char* netmask;
};

// 接收的参数
struct GetParam {
    pcap_t* adhandle;
};

// 打印发送端菜单
bool SenderMenu(pcap_if_t* alldevs) {
    int index;  // 适配器个数
    int choice;
    while (true) {
        printf("================================发 送 端=================================\n");
        printf("\t当前系统中有以下网络适配器\n");
        index = 0;  // 适配器个数初始化
        for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
            index++;
            printf("%d. %s\n", index, dev->name);
            if (dev->addresses == NULL)
                continue;
            switch (dev->addresses->addr->sa_family) {  // sa_family代表了地址的类型（IPV4地址类型/IPV6地址）
                case AF_INET:                           // 代表IPV4类型地址
                    printf("IP地址类型:IPv4\n");
                    if (dev->addresses->addr) {
                        printf("IPv4地址:%s\n", iptos(((struct sockaddr_in*)dev->addresses->addr)->sin_addr.s_addr));
                    }
                    break;
                case AF_INET6:  // 代表IPV6类型地址
                    printf("IP地址类型:IPv6\n");
                    if (dev->addresses->addr) {
                        char ip6str[128];
                        printf("IPv6地址: %s\n", ip6tos(dev->addresses->addr, ip6str, sizeof(ip6str)));
                    }
                    break;
                default:
                    printf("\t未知的IP地址类型\n");
                    break;
            }
        }
        printf("---------------------------检测到适配器个数: %d--------------------------\n", index);
        // i为0即没有找到适配器,可能的原因为Npcap没有安装导致未扫描到
        if (index == 0) {
            printf("没有找到适配器，请检查Npcap安装情况\n");
            system("pause");
            exit(30);
        }

        printf("1.查看适配器详情\n");
        printf("2.发送数据包\n");
        printf("3.退出\n");
        printf("请选择操作:");
        // 让用户选择操作
        scanf("%d", &choice);
        system("cls");
        int i = 0;
        switch (choice) {
                /*打印适配器详细信息*/
            case 1: {
                PrintDevMenu(alldevs, index);
                break;
            }
                /*发送数据包*/
            case 2: {
                SendPack(alldevs, index);
                break;
            }
                /*退出*/
            case 3: {
                pcap_freealldevs(alldevs);
                return false;
            }
            default:
                printf("输入的序号超出范围！\n");
                system("pause");
                system("cls");
                break;
        }
    }
}

// 打印适配器信息
void PrintDevMenu(pcap_if_t* dev, const int& inum) {
    pcap_if_t* d = dev;
    int i, index;

    while (true) {
        printf("---------------打印适配器信息-----------------\n");
        printf("选择一个适配器(1~%d; 0:退出):", inum);
        // 让用户选择选择哪个适配器信息打印
        scanf("%d", &index);
        printf("\n");

        if (index == 0) {
            break;
        }

        // 用户输入的数字超出合理范围返回
        if (index < 0 || index > inum) {
            printf("输入的序号超出范围！\n");
            printf("请重新进行选择\n");
            system("pause");
            system("cls");
            continue;
        }
        //  跳转到选中的适配器
        for (i = 0; i < index - 1; d = d->next, i++)
            ;
        // 打印该适配器信息
        ifprint(d, i);
    }
    system("cls");
}

// 发送报文
void SendPack(pcap_if_t* alldevs, const int& inum) {
    int i = 0;
    pcap_if_t* d;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    while (true) {
        printf("-------------发送数据包-------------\n");
        printf("选择一个适配器(1~%d;0:退出):", inum);
        // 让用户选择选择哪个适配器进行抓包
        scanf("%d", &i);
        printf("\n");

        // 用户输入的数字超出合理范围，并释放适配器列表
        if (i < 0 || i > inum) {
            printf("输入的序号超出范围！\n");
            system("pause");
            system("cls");
            continue;
        }
        if (i == 0) {
            printf("退出回到菜单\n");
            // pcap_freealldevs(alldevs);
            system("pause");
            system("cls");
            return;
        }
        int index;
        // 跳转到选中的适配器
        for (d = alldevs, index = 0; index < i - 1; d = d->next, index++)
            ;

        // 打开选中的适配器
        adhandle = pcap_open(d->name,                    // 设备名称
                             MTU_SIZE,                   //  65535保证能捕获到数据链路层上的每个数据包的全部内容
                             PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                             TIME_OUT,                   // 超时时间
                             NULL,                       // 远程机器验证
                             errbuf                      // 错误缓冲池
        );

        // 打开适配器失败,打印错误并释放适配器列表
        if (adhandle == NULL) {
            fprintf(stderr, "\n无法打开适配器，Npcap不支持 %s\n", d->name);
            // 释放设备列表
            pcap_freealldevs(alldevs);
            system("pause");
            system("cls");
            return;
        }
        PutGetArp(adhandle, d, i);  // 发送ARP请求，获取当前网卡IP和MAC地址
    }
}

// 发送和接收ARP帧
void PutGetArp(pcap_t* adhandle, pcap_if_t* d, const int& i) {
    // 开启2个线程：发送线程和接收线程，用于实现ARP地址解析
    char* ip_addr = (char*)malloc(sizeof(char) * 16);      // IP地址
    char* ip_netmask = (char*)malloc(sizeof(char) * 16);   // 子网掩码
    u_char* ip_mac = (u_char*)malloc(sizeof(u_char) * 6);  // 本机MAC地址
    // 要发送和接收的ARP分组
    SendParam sp;
    GetParam gp;
    char choice;
    getIP(d, ip_addr, ip_netmask);          // 获取所选网卡的基本信息：IP和子网掩码
    getSelfMAC(adhandle, ip_addr, ip_mac);  // 获取当前主机的MAC地址
    sp.adhandle = adhandle;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle;
    HANDLE sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_send_arp, &sp, 0, NULL);
    HANDLE recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_live_ip, &gp, 0, NULL);
    printf("\n监听 %d 号网卡 ...\n", i);
    getchar();  // 吸收Enter
    while (true) {
        FillEthFrame(ip_mac, ip_addr, adhandle);
        printf("是否继续发送(y/n):");
        scanf("%c", &choice);
        system("cls");
        if (choice != 'y' && choice != 'Y')
            break;
        printf("\n请输入你要发送对方的IP地址:\n");
    }
    return;
}

// 【数据链路层】填充以太网帧
void FillEthFrame(const u_char* ip_mac, const char* ip_addr, pcap_t* adhandle) {
    char* send_data = (char*)malloc(sizeof(char) * 50);  // 申请内存存放要发送的数据
    if (send_data == NULL) {
        printf("申请内存存放要发送的数据空间失败!\n");
        return;
    }
    ethernet_header eh;    // 以太网帧头
    u_char send_buf[200];  // 发送队列
    ipv4_num ipv4_n;
    scanf("%hd.%hd.%hd.%hd", &ipv4_n.ip1, &ipv4_n.ip2, &ipv4_n.ip3, &ipv4_n.ip4);
    printf("请输入你要发送的内容:\n");
    getchar();  // 吸收Enter
    std::cin.getline(send_data, MAX_STR_SIZE);
    printf("要发送的内容为:%s\n", send_data);
    system("cls");

    // ANCHOR - 填充以太网MAC帧
    /* -------------------------------- 填充以太网MAC帧 ------------------------------- */
    // 目的MAC地址（由于网卡开启了混杂模式，不赋值为本网卡MAC地址也可以捕捉到并解析）
    BYTE destmac[6] = {0x82, 0xf0, 0x7f, 0x44, 0x98, 0x6d};  // 点对点链路上的另一个网卡的MAC地址
    // 0xe0, 0xde, 0xe8, 0x63, 0xc1, 0xf3
    memcpy(&(eh.des_mac_addr), destmac, 6);
    // 源MAC地址
    BYTE hostmac[6];
    memcpy(hostmac, ip_mac, 6);  // 这里我自己发给自己，就让源mac地址是自己的源mac地址
    // 源MAC地址
    memcpy(&(eh.src_mac_addr), hostmac, 6);
    // 上层协议类型
    eh.type = htons(ETH_IPV4);
    // 赋值send_buf
    memcpy(&send_buf, &eh, sizeof(ethernet_header));

    // 填充IP数据报
    FillIPData(ipv4_n, send_buf, send_data, ip_addr, adhandle);
    free(send_data);  // 及时释放读入的数据
    return;
}

// 【网络层】填充IP数据报
void FillIPData(ipv4_num& ipv4_n, u_char* send_buf, char* tcp_data, const char* ip_addr, pcap_t* adhandle) {
    ipv4_header ipv4;  // IP头
    // ANCHOR - 填充IP数据报
    /* --------------------------------- 填充IP数据报 -------------------------------- */
    // 填充IP头部
    ipv4.ver_hlen = 0x45;  // IPv4+5*32bit 由于只有1个字节，无需转化为网络字节序
    ipv4.tos = 0;          // 不使用
    ipv4.tlen = htons(sizeof(ipv4_header) + sizeof(tcp_header) + strlen(tcp_data));
    ipv4.id = htons(1);
    ipv4.flags_offset = 0;  // _ DF MF
    ipv4.ttl = 128;
    ipv4.protocol = 6;  // TCP协议
    ipv4.checksum = 0;  // 检验和字段先置零
    // 源IP地址(设为当前网卡IP地址)
    ipv4.src_ip_addr.bin_fmt = inet_addr(ip_addr);  // inet_addr("192.168.43.40");
    // 目的IP地址
    ipv4.des_ip_addr.dot_fmt.byte1 = ipv4_n.ip1;
    ipv4.des_ip_addr.dot_fmt.byte2 = ipv4_n.ip2;
    ipv4.des_ip_addr.dot_fmt.byte3 = ipv4_n.ip3;
    ipv4.des_ip_addr.dot_fmt.byte4 = ipv4_n.ip4;
    // 赋值sendbuf以IP数据报首部固定部分(由于没有可变部分，正好对齐4字节)
    memcpy(&send_buf[sizeof(ethernet_header)], &ipv4, 20);

    // 填充TCP报文
    FillTCPData(ipv4, send_buf, tcp_data, adhandle);
    return;
}

// 【运输层】填充TCP报文
void FillTCPData(ipv4_header& ipv4, u_char* send_buf, char* tcp_data, pcap_t* adhandle) {
    tcp_header tcp;       // TCP头
    psd_tcp_header ptcp;  // TCP伪首部
    // ANCHOR - 填充TCP报文
    /* --------------------------------- 填充TCP报文 -------------------------------- */
    // 赋值TCP首部
    tcp.sport = htons(SRC_PORT);
    tcp.dport = htons(DEST_PORT);
    tcp.seq = htonl(SEQ_NUM);
    tcp.ack = ACK_NUM;
    tcp.offset = 0x50;
    tcp.flags = 0x18;  // 0 1 0 0 1 0
    tcp.window = htons(512);
    tcp.checksum = 0;  // 先放全0
    tcp.urg = 0;       // 不使用URG，因此不用紧急指针

    // 赋值send_buf
    memcpy(&send_buf[sizeof(ethernet_header) + 20], &tcp, 20);
    // 赋值伪首部
    ptcp.src_addr = ipv4.src_ip_addr;
    ptcp.des_addr = ipv4.des_ip_addr;
    ptcp.zero = 0;
    ptcp.protcol = IP_TCP;
    ptcp.tcp_len = htons(sizeof(tcp_header) + strlen(tcp_data));
    char temp_buf[MTU_SIZE];
    memcpy(temp_buf, &ptcp, sizeof(psd_tcp_header));
    // 拼接TCP报文
    memcpy(temp_buf + sizeof(psd_tcp_header), &tcp, sizeof(tcp_header));
    memcpy(temp_buf + sizeof(psd_tcp_header) + sizeof(tcp_header), tcp_data, strlen(tcp_data));
    // 计算TCP的校验和
    tcp.checksum = checksum((USHORT*)(temp_buf), sizeof(psd_tcp_header) + sizeof(tcp_header) + strlen(tcp_data));
    // 更新send_buf，因为其中TCP检验和字段已更新
    memcpy(send_buf + sizeof(ethernet_header) + sizeof(ipv4_header), &tcp, sizeof(tcp_header));
    memcpy(send_buf + sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header), tcp_data, strlen(tcp_data));

    // 初始化temp_buf为0序列，存储变量来计算IP校验和
    memset(temp_buf, 0, sizeof(temp_buf));
    memcpy(temp_buf, &ipv4, sizeof(ipv4_header));
    // 计算IP校验和
    ipv4.checksum = checksum((USHORT*)(temp_buf), sizeof(ipv4_header));
    // 重新把send_buf赋值，IP校验和已经改变
    memcpy(send_buf + sizeof(ethernet_header), &ipv4, sizeof(ipv4_header));

    int size = sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header) + strlen(tcp_data);
    if (pcap_sendpacket(adhandle, send_buf, size) != 0) {
        printf("=>发送失败!\n");
    } else {
        printf("=>发送TCP数据包.\n");
        printf("目的端口:%d\n", ntohs(tcp.dport));
        printf("源端口:%d\n", ntohs(tcp.sport));
        printf("序号:%d\n", ntohl(tcp.seq));
        printf("确认号:%d\n", ntohl(tcp.ack));
        printf("首部长度:%d*4\n", tcp.offset >> 4);
        printf("标志位:0x%0x\n", ntohs(tcp.flags));
        printf("窗口大小:%d\n", ntohs(tcp.window));
        printf("检验和:%u\n", ntohs(tcp.checksum));
        printf("紧急指针:%d\n", ntohs(tcp.urg));
        printf("=>发送成功!\n");
    }
    return;
}

/* -------------------------------------------------------------------------- */
/*                                    接收                                    */
/* -------------------------------------------------------------------------- */
std::unordered_map<std::string, int> dumpMsg;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    std::cout << B_DIVISION << "时间戳:" << timestr << ","
              << header->ts.tv_usec << "  长度:" << header->len << B_DIVISION << std::endl;
    ethernet_package_handler(param, header, pkt_data);  // 从以太网MAC帧开始层层解包
}

void ethernet_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ethernet_header* eh = (ethernet_header*)pkt_data;
    std::cout << DIVISION << "以太网MAC帧内容" << DIVISION << std::endl;
    u_short type = ntohs(eh->type);
    std::cout << "类型：0x" << std::hex << type;
    std::cout << std::setbase(10);
    switch (type) {
        case ETH_IPV4:
            std::cout << " (IPv4)" << std::endl;
            break;
        case ETH_IPV6:
            std::cout << "(IPv6)" << std::endl;
            break;
        case ETH_ARP:
            std::cout << " (ARP)" << std::endl;
            break;
        case ETH_RARP:
            std::cout << " (RARP)" << std::endl;
        default:
            break;
    }
    std::cout << "目的地址：" << int(eh->des_mac_addr.byte1) << ":"
              << int(eh->des_mac_addr.byte2) << ":"
              << int(eh->des_mac_addr.byte3) << ":"
              << int(eh->des_mac_addr.byte4) << ":"
              << int(eh->des_mac_addr.byte5) << ":"
              << int(eh->des_mac_addr.byte6) << std::endl;
    std::cout << "源地址：" << int(eh->src_mac_addr.byte1) << ":"
              << int(eh->src_mac_addr.byte2) << ":"
              << int(eh->src_mac_addr.byte3) << ":"
              << int(eh->src_mac_addr.byte4) << ":"
              << int(eh->src_mac_addr.byte5) << ":"
              << int(eh->src_mac_addr.byte6) << std::endl;
    switch (type) {
        case ETH_IPV4:
            ip_v4_package_handler(param, header, pkt_data);
            break;
        case ETH_ARP:
            arp_package_handler(param, header, pkt_data);
            break;
        case ETH_IPV6:
            ip_v6_package_handler(param, header, pkt_data);
            break;
        default:
            break;
    }
    std::cout << std::endl
              << std::endl;
}

void arp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    arp_header* ah;
    ah = (arp_header*)(pkt_data + 14);
    std::cout << DIVISION << "ARP帧内容" << DIVISION << std::endl;
    u_short operation_code = ntohs(ah->operation_code);
    std::cout << "硬件类型：" << ntohs(ah->hardware_type) << std::endl;
    std::cout << "协议类型：0x" << std::hex << ntohs(ah->protocol_type) << std::endl;
    std::cout << std::setbase(10);
    std::cout << "硬件地址长度：" << int(ah->hardware_length) << std::endl;
    std::cout << "协议地址长度：" << int(ah->protocol_length) << std::endl;
    switch (operation_code) {
        case 1:
            std::cout << "ARP请求协议" << std::endl;
            break;
        case 2:
            std::cout << "ARP应答协议" << std::endl;
            break;
        case 3:
            std::cout << "ARP请求协议" << std::endl;
            break;
        case 4:
            std::cout << "RARP应答协议" << std::endl;
            break;
        default:
            break;
    }
    std::cout << "源IP地址："
              << int(ah->src_ip_addr.dot_fmt.byte1) << "."
              << int(ah->src_ip_addr.dot_fmt.byte2) << "."
              << int(ah->src_ip_addr.dot_fmt.byte3) << "."
              << int(ah->src_ip_addr.dot_fmt.byte4) << std::endl;

    std::cout << "目的IP地址："
              << int(ah->des_ip_addr.dot_fmt.byte1) << "."
              << int(ah->des_ip_addr.dot_fmt.byte2) << "."
              << int(ah->des_ip_addr.dot_fmt.byte3) << "."
              << int(ah->des_ip_addr.dot_fmt.byte4) << std::endl;

    add_to_map(dumpMsg, ah->src_ip_addr);
    print_map(dumpMsg);
}

void ip_v4_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ipv4_header* ih;
    ih = (ipv4_header*)(pkt_data + 14);  // 14 measn the length of ethernet header
    std::cout << DIVISION << "IPv4数据报内容" << DIVISION << std::endl;
    std::cout << "版本号：" << ((ih->ver_hlen & 0xf0) >> 4) << std::endl;
    std::cout << "首部长度：" << (ih->ver_hlen & 0xf) << "("
              << ((ih->ver_hlen & 0xf) << 2) << "B)" << std::endl;
    std::cout << "区别服务：" << int(ih->tos) << std::endl;
    std::cout << "总长度：" << ntohs(ih->tlen) << std::endl;
    std::cout << "标识：" << ntohs(ih->id) << std::endl;
    std::cout << "标志：" << ((ih->flags_offset & 0xE000) >> 12) << std::endl;
    std::cout << "片偏移：" << (ih->flags_offset & 0x1FFF) << "("
              << ((ih->flags_offset & 0x1FFF) << 3) << "B)" << std::endl;
    std::cout << "生命周期：" << int(ih->ttl) << std::endl;
    std::cout << "协议：";
    switch (ih->protocol) {
        case 6:
            std::cout << "TCP" << std::endl;
            break;
        case 17:
            std::cout << "UDP" << std::endl;
            break;
        case 1:
            std::cout << "ICMP" << std::endl;
            break;
        default:
            std::cout << std::endl;
            break;
    }
    std::cout << "校验和：" << ntohs(ih->checksum) << std::endl;
    std::cout << "源IP地址："
              << int(ih->src_ip_addr.dot_fmt.byte1) << "."
              << int(ih->src_ip_addr.dot_fmt.byte2) << "."
              << int(ih->src_ip_addr.dot_fmt.byte3) << "."
              << int(ih->src_ip_addr.dot_fmt.byte4) << std::endl;

    std::cout << "目的IP地址："
              << int(ih->des_ip_addr.dot_fmt.byte1) << "."
              << int(ih->des_ip_addr.dot_fmt.byte2) << "."
              << int(ih->des_ip_addr.dot_fmt.byte3) << "."
              << int(ih->des_ip_addr.dot_fmt.byte4) << std::endl;
    switch (ih->protocol) {
        case IP_TCP:
            tcp_package_handler(param, header, pkt_data);
            break;
        case IP_UDP:
            udp_package_handler(param, header, pkt_data);
            break;
        case IP_ICMPV4:
            icmp_package_handler(param, header, pkt_data);
            break;
        default:
            break;
    }
    add_to_map(dumpMsg, ih->src_ip_addr);
    print_map(dumpMsg);
}

void ip_v6_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ipv6_header* ih;
    ih = (ipv6_header*)(pkt_data + 14);  // 14 measn the length of ethernet header
    int version = (ih->ver_trafficclass_flowlabel & 0xf0000000) >> 28;
    int traffic_class = ntohs((ih->ver_trafficclass_flowlabel & 0x0ff00000) >> 20);
    int flow_label = ih->ver_trafficclass_flowlabel & 0x000fffff;
    std::cout << "版本号：" << version << std::endl;
    std::cout << "通信量类：" << traffic_class << std::endl;
    std::cout << "流标号：" << flow_label << std::endl;
    std::cout << "有效载荷：" << ntohs(ih->payload_len) << std::endl;
    std::cout << "下一个首部：" << int(ih->next_head) << std::endl;
    std::cout << "跳数限制：" << int(ih->ttl) << std::endl;
    std::cout << "源IP地址："
              << int(ih->src_ip_addr.part1) << ":"
              << int(ih->src_ip_addr.part2) << ":"
              << int(ih->src_ip_addr.part3) << ":"
              << int(ih->src_ip_addr.part4) << ":"
              << int(ih->src_ip_addr.part5) << ":"
              << int(ih->src_ip_addr.part6) << ":"
              << int(ih->src_ip_addr.part7) << ":"
              << int(ih->src_ip_addr.part8) << std::endl;
    std::cout << "目的IP地址："
              << int(ih->dst_ip_addr.part1) << ":"
              << int(ih->dst_ip_addr.part2) << ":"
              << int(ih->dst_ip_addr.part3) << ":"
              << int(ih->dst_ip_addr.part4) << ":"
              << int(ih->dst_ip_addr.part5) << ":"
              << int(ih->dst_ip_addr.part6) << ":"
              << int(ih->dst_ip_addr.part7) << ":"
              << int(ih->dst_ip_addr.part8) << std::endl;
    switch (ih->next_head) {
        case IP_TCP:
            tcp_package_handler(param, header, pkt_data);
            break;
        case IP_UDP:
            udp_package_handler(param, header, pkt_data);
            break;
        case IP_ICMPV6:
            icmp_package_handler(param, header, pkt_data);
            break;
        default:
            break;
    }
    add_to_map(dumpMsg, ih->src_ip_addr);
    print_map(dumpMsg);
}

void udp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    udp_header* uh;
    uh = (udp_header*)(pkt_data + 20 + 14);
    std::cout << DIVISION << "UDP报文内容" << DIVISION << std::endl;
    std::cout << "源端口：" << ntohs(uh->sport) << std::endl;
    std::cout << "目的端口：" << ntohs(uh->dport) << std::endl;
    std::cout << "长度：" << ntohs(uh->len) << std::endl;
    std::cout << "检验和：" << ntohs(uh->checksum) << std::endl;
}

void tcp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    tcp_header* th;
    th = (tcp_header*)(pkt_data + 14 + 20);
    char* data = (char*)((u_char*)th + 20);
    std::cout << DIVISION << "TCP报文内容" << DIVISION << std::endl;
    std::cout << "源端口：" << ntohs(th->sport) << std::endl;
    std::cout << "目的端口：" << ntohs(th->dport) << std::endl;
    std::cout << "序号：" << ntohl(th->seq) << std::endl;
    std::cout << "确认号：" << ntohl(th->ack) << std::endl;
    std::cout << "数据偏移：" << ((th->offset & 0xf0) >> 4) << "("
              << ((th->offset & 0xf0) >> 2) << "B)" << std::endl;
    std::cout << "标志：";
    if (th->flags & 0x01) {
        std::cout << "FIN ";
    }
    if (th->flags & 0x02) {
        std::cout << "SYN ";
    }
    if (th->flags & 0x04) {
        std::cout << "RST ";
    }
    if (th->flags & 0x08) {
        std::cout << "PSH ";
    }
    if (th->flags & 0x10) {
        std::cout << "ACK ";
    }
    if (th->flags & 0x20) {
        std::cout << "URG ";
    }
    std::cout << std::endl;
    std::cout << "窗口：" << ntohs(th->window) << std::endl;
    std::cout << "检验和：" << ntohs(th->checksum) << std::endl;
    std::cout << "紧急指针：" << ntohs(th->urg) << std::endl;
    std::cout << "数据部分：" << data << std::endl;
}

void icmp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    icmp_header* ih;
    ih = (icmp_header*)(pkt_data + 14 + 20);
    std::cout << DIVISION << "ICMP报文内容" << DIVISION << std::endl;
    std::cout << "ICMP类型：" << ih->type;
    switch (ih->type) {
        case 8:
            std::cout << "ICMP回显请求协议" << std::endl;
            break;
        case 0:
            std::cout << "ICMP回显应答协议" << std::endl;
            break;
        default:
            break;
    }
    std::cout << "ICMP代码：" << ih->code << std::endl;
    std::cout << "标识符：" << ih->id << std::endl;
    std::cout << "序列码：" << ih->sequence << std::endl;
    std::cout << "ICMP校验和：" << ntohs(ih->checksum) << std::endl;
}

void add_to_map(std::unordered_map<std::string, int>& dump, ipv4_address& ip) {
    std::string ip_string;
    int amount = 0;
    std::unordered_map<std::string, int>::iterator iter;
    ip_string = std::to_string(ip.dot_fmt.byte1) + "." + std::to_string(ip.dot_fmt.byte2) + "." + std::to_string(ip.dot_fmt.byte3) + "." + std::to_string(ip.dot_fmt.byte4);
    iter = dump.find(ip_string);
    if (iter != dump.end()) {
        amount = iter->second;
    }
    dump.insert_or_assign(ip_string, ++amount);
}

void add_to_map(std::unordered_map<std::string, int>& dump, ipv6_address& ip) {
    std::string ip_string;
    int amount = 0;
    std::unordered_map<std::string, int>::iterator iter;
    ip_string = std::to_string(ip.part1) + ":" + std::to_string(ip.part2) + ":" + std::to_string(ip.part3) + ":" + std::to_string(ip.part4) + ":" + std::to_string(ip.part5) + ":" + std::to_string(ip.part6) + ":" + std::to_string(ip.part7) + ":" + std::to_string(ip.part8);
    iter = dump.find(ip_string);
    if (iter != dump.end()) {
        amount = iter->second;
    }
    dump.insert_or_assign(ip_string, ++amount);
}

void print_map(std::unordered_map<std::string, int> dump) {
    std::ofstream ofs_flow;
    ofs_flow.open("flowDump.txt", std::ios::out | std::ios::trunc);
    std::unordered_map<std::string, int>::iterator iter;
    std::cout << DIVISION << "流量统计" << DIVISION << std::endl;
    ofs_flow << DIVISION << "流量统计" << DIVISION << std::endl;
    std::cout << "IP" << std::setfill(' ') << std::setw(45) << "流量" << std::endl;
    ofs_flow << "IP" << std::setfill(' ') << std::setw(45) << "流量" << std::endl;
    for (iter = dump.begin(); iter != dump.end(); iter++) {
        std::cout << iter->first << std::setfill('.') << std::setw(45 - iter->first.length()) << iter->second << std::endl;
        ofs_flow << iter->first << std::setfill('.') << std::setw(45 - iter->first.length()) << iter->second << std::endl;
    }
    ofs_flow.close();
}

// 打印接收端菜单
bool RecieveMenu(pcap_if_t* alldevs) {
    int index;  // 适配器索引
    int choice;
    char errbuf[PCAP_ERRBUF_SIZE];
    while (true) {
        printf("================================接 收 端=================================\n");
        printf("\t当前系统中有以下网络适配器\n");
        index = 0;  // 适配器索引初始化
        for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
            index++;
            printf("%d. %s\n", index, dev->name);
        }
        printf("---------------------------检测到适配器个数: %d--------------------------\n", index);
        // i为0即没有找到适配器,可能的原因为Npcap没有安装导致未扫描到
        if (index == 0) {
            printf("没有找到适配器，请检查Npcap安装情况\n");
            system("pause");
            exit(30);
        }

        printf("1.查看适配器详情\n");
        printf("2.接收数据包\n");
        printf("3.退出\n");
        printf("请选择操作:");
        scanf("%d", &choice);
        system("cls");
        int i = 0;
        switch (choice) {
            case 1: {
                PrintDevMenu(alldevs, index);
                break;
            }
                /*接收数据包*/
            case 2: {
                RecivePack(alldevs, index, errbuf);
                break;
            }
                /*退出*/
            case 3: {
                pcap_freealldevs(alldevs);
                return false;
            }

            default:
                printf("输入的序号超出范围！\n");
                system("pause");
                system("cls");
                break;
        }
    }
}

// 接收数据
void RecivePack(pcap_if_t* alldevs, const int& inum, char* errbuf) {
    pcap_if_t* d;
    pcap_t* adhandle;
    int i;
    /*输出列表*/
    /*for (d = alldevs; d != NULL; d = d->next) {
            ifprint(d, inum);
    }*/
    if (inum == 0) {
        printf("\n没有找到接口!确保安装了Npcap.\n");
        // getchar();
        return;
    }
    printf("=====================开始接收数据包================\n");
    printf("选择一个适配器(1~%d):", inum);
    scanf("%d", &i);
    if (i < 1 || i > inum) {
        printf("输入的序号超出范围！\n");
        pcap_freealldevs(alldevs);
        return;
    }

    // 转到选择的设备
    d = alldevs;
    for (int j = 0; j < i - 1; d = d->next, j++)
        ;
    // 打开失败
    if ((adhandle = pcap_open_live(d->name, MTU_SIZE, 1, TIME_OUT, errbuf)) == NULL) {
        fprintf(stderr, "\n无法打开适配器，Npcap不支持 %s\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }
    Monitors(adhandle, d);
    return;
}

// 监听指定的网卡
void Monitors(pcap_t* adhandle, pcap_if_t* d) {
    u_int netmask = 0xffffff;
    struct bpf_program fcode;
    int pktnum;
    std::string rule = "ip or arp";  // 默认过滤规则
    char r;

    // 设置过滤规则引擎
    std::string src_ip, dst_port;
    printf("=====设置过滤规则(d表示默认全部监听)=====\n");
    getchar();  // 吸收回车
    scanf("%c", &r);
    if (r != 'd') {
        printf("请输入需要监听的主机的IP地址：\n");
        std::cin >> src_ip;
        printf("请输入需要监听的主机上的端口号：\n");
        std::cin >> dst_port;
        rule = "src host " + src_ip + " && dst port " + dst_port;
    }

    if (pcap_compile(adhandle, &fcode, rule.c_str(), 1, netmask) < 0) {
        fprintf(stderr, "\n无法编译包过滤器。请检查BPF语法。\n");
        pcap_close(adhandle);
        return;
    }

    // 启用过滤规则引擎
    if (pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "\n设置过滤器错误。\n");
        pcap_close(adhandle);
        return;
    }

    printf("请输入你想要捕获的数据包数量(0表示持续捕获): \n");
    scanf("%d", &pktnum);

    // 开始捕捉
    std::cout << "当前过滤规则是: " + rule << std::endl;
    printf("\n监听网卡: %s ...\n", d->description);

    // ofs.open("getLog.txt", std::ios::out | std::ios::trunc);
    pcap_loop(adhandle, pktnum, packet_handler, NULL);

    pcap_close(adhandle);
    // ofs.close();
    getchar();
    printf("监听结束");
    system("pause");
    system("cls");
}