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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "net-types.h"
#include "utils.h"

#define MAX_STR_SIZE 500    // 从控制台允许的最大输入长度
#define MTU_SIZE 65535      // 最大传输单元长度
#define TIME_OUT 1000       // 超时时间
#define HOST_NUM 255        // 主机数量
#define IP_PROTOCOL 0x0800  // IP协议的协议类型号
#define TCP_PROTOCOL 6      //TCP的协议号
#define DEST_PORT 102       // 目的端口号
#define SRC_PORT 1000       // 源端口号
#define SEQ_NUM 11
#define ACK_NUM 0

/* ---------------------------------- 函数声明 ---------------------------------- */

void ifprint(pcap_if_t* dev, int& i);
char* iptos(u_long in);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);
void thread_getIP(pcap_if_t* d, char* ip_addr, char* ip_netmask);          // 用ifget方法获取自身的IP和子网掩码
int thread_getSelfMAC(pcap_t* adhandle, const char* ip_addr, u_char* ip_mac);  // 发送一个ARP请求来获取自身的MAC地址
u_short checksum(u_short* data, int length);                            // 校验和方法
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);

/* ---------------------------------- 全局变量声明 ---------------------------------- */

bool flag;
HANDLE sendthread;  // 发送ARP包线程
HANDLE recvthread;  // 接受ARP包线程
#pragma pack(1)     // 按一个字节内存对齐

// 要发送和接收的ARP分组
SendParam sp;
struct GetParam gp;

int main() {
    /* 准备IP地址相关数据的内存，用于之后构造分组 */
    char* ip_addr;     // IP地址
    char* ip_netmask;  // 子网掩码
    u_char* ip_mac;    // 本机MAC地址
    /* 为这三个变量分配地址空间*/
    ip_addr = ALLOCATE(char, 16)  // 申请内存存放IP地址
                                  // ip_addr = (char*)malloc(sizeof(char) * 16);  // 申请内存存放IP地址
        if (ip_addr == NULL) {
        printf("申请内存存放IP地址失败!\n");
        return -1;
    }
    ip_netmask = ALLOCATE(char, 16)  // 申请内存存放NETMASK地址
                                     // ip_netmask = (char*)malloc(sizeof(char) * 16);  // 申请内存存放NETMASK地址
        if (ip_netmask == NULL) {
        printf("申请内存存放NETMASK地址失败!\n");
        return -1;
    }
    ip_mac = ALLOCATE(u_char, 6)  // 申请内存存放MAC地址
                                  // ip_mac = (u_char*)malloc(sizeof(u_char) * 6);  // 申请内存存放MAC地址
        if (ip_mac == NULL) {
        printf("申请内存存放MAC地址失败!\n");
        return -1;
    }

    /* 获取本机的网络适配器列表，由用户选择一个作为Sender */
    pcap_if_t* alldevs;             // 所有网络适配器
    pcap_if_t* dev;                 // 选中的网络适配器
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区,长度为256B
    pcap_t* adhandle;               // 捕捉实例,是pcap_open返回的对象
    int i = 0;                      // 适配器计数索引
    // 获取本地适配器列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        // 结果为-1代表出现获取适配器列表失败
        fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
        exit(1);
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        ifprint(dev, i);
    }
    // i为0即没有找到适配器,可能的原因为Winpcap没有安装导致未扫描到
    if (i == 0) {
        printf("没有找到适配器，请检查Winpcap安装情况");
    }

    int num;
    printf("选择一个适配器(1~%d):", i);
    // 让用户选择选择哪个适配器进行抓包
    scanf("%d", &num);
    printf("\n");

    // 用户输入的数字超出合理范围，并释放适配器列表
    if (num < 1 || num > i) {
        printf("输入的序号超出范围！\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 跳转到选中的适配器
    for (dev = alldevs, i = 0; i < num - 1; dev = dev->next, i++)
        ;

    // 打开选中的适配器
    adhandle = pcap_open(dev->name,                  // 设备名称
                         MTU_SIZE,                   //  65535保证能捕获到数据链路层上的每个数据包的全部内容
                         PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                         TIME_OUT,                   // 超时时间
                         NULL,                       // 远程机器验证
                         errbuf                      // 错误缓冲池
    );

    // 打开适配器失败,打印错误并释放适配器列表
    if (adhandle == NULL) {
        fprintf(stderr, "\n无法打开适配器，Winpcap不支持 %s\n", dev->name);
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 开启2个线程：发送线程和接收线程，用于实现ARP地址解析
    // 对sp和gp两个ARP请求所需要的结构体进行赋值
    thread_getIP(dev, ip_addr, ip_netmask);    // 获取所选网卡的基本信息：IP和子网掩码
    thread_getSelfMAC(adhandle, ip_addr, ip_mac);  // 获取当前主机的MAC地址
    sp.adhandle = adhandle;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle;
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket, &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetLivePC, &gp, 0, NULL);

    printf("\n监听 %d 号网卡 ...\n", i + 1);
    pcap_freealldevs(alldevs);
    getchar();//吸收Enter

    while (true) {
        char* tcp_data = (char*)malloc(sizeof(char) * 50);  // 申请内存存放要发送的数据
        if (tcp_data == NULL) {
            printf("申请内存存放要发送的数据!\n");
            return -1;
        }
        EthernetHeader ethernet;  // 以太网帧头,初始化针头全为0序列
        struct IpHeader ip;              // IP头
        struct TcpHeader tcp;            // TCP头
        struct PsdTcpHeader ptcp;        // TCP伪首部
        u_char send_buffer[200];          // 发送队列
        IPv4 ipv4;
        scanf("%hd.%hd.%hd.%hd", &ipv4.ip1, &ipv4.ip2, &ipv4.ip3, &ipv4.ip4);
        printf("请输入你要发送的内容:\n");
        getchar();//吸收Enter
        std::cin.getline(tcp_data, MAX_STR_SIZE);
        // gets(tcp_data);
        printf("要发送的内容为:%s\n", tcp_data);

        // SECTION - 填充以太网MAC帧
        /* -------------------------------- 填充以太网MAC帧 ------------------------------- */
        // 以太网帧头初始化为全0序列
        //memset(&ethernet, 0, sizeof(ethernet));
        // 目的MAC地址,此处没有对帧的MAC地址进行赋值，因为网卡设置的混杂模式，可以接受经过该网卡的所有帧。
        // 当然最好的方法是赋值为ARP刚才获取到的MAC地址，当然不赋值也可以捕捉到并解析。
        BYTE destmac[8];
        memcpy(destmac, ip_mac, 6);
        // destmac[0] = 0x00;
        // destmac[1] = 0x11;
        // destmac[2] = 0x22;
        // destmac[3] = 0x33;
        // destmac[4] = 0x44;
        // destmac[5] = 0x55;
        // 目的MAC地址
        memcpy(ethernet.dest_mac, destmac, 6);
        // 源MAC地址
        BYTE hostmac[8];
        memcpy(hostmac, ip_mac, 6);
        // hostmac[0] = 0x00;
        // hostmac[1] = 0x1a;
        // hostmac[2] = 0x4d;
        // hostmac[3] = 0x70;
        // hostmac[4] = 0xa3;
        // hostmac[5] = 0x89;
        // 源MAC地址
        memcpy(ethernet.source_mac, hostmac, 6);
        // 上层协议类型
        ethernet.ether_type = htons(IP_PROTOCOL);
        // 赋值SendBuffer
        memcpy(&send_buffer, &ethernet, sizeof(struct EthernetHeader));
        //!SECTION

        // SECTION - 填充IP数据报
        /* --------------------------------- 填充IP数据报 -------------------------------- */
        // 赋值IP头部信息
        ip.version_hlen = 0x45;  // IPv4+5*32bit 由于只有1个字节，无需转化为网络字节序
        ip.ip_tos = 0;           // 不使用
        ip.ip_length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(tcp_data));
        ip.ip_id = htons(1);
        ip.ip_flag_off = 0;  // _ DF MF
        ip.ip_ttl = 128;
        ip.ip_protocol = 6;  // TCP协议
        ip.ip_checksum = 0;  // 检验和字段先置零
        // 源IP地址(设为本机IP地址)
        ip.ip_souce_address.byte1 = 127;
        ip.ip_souce_address.byte2 = 0;
        ip.ip_souce_address.byte3 = 0;
        ip.ip_souce_address.byte4 = 1;
        // 目的IP地址
        ip.ip_destination_address.byte1 = ipv4.ip1;
        ip.ip_destination_address.byte2 = ipv4.ip2;
        ip.ip_destination_address.byte3 = ipv4.ip3;
        ip.ip_destination_address.byte4 = ipv4.ip4;
        // 赋值SendBuffer以IP数据报首部固定部分(由于没有可变部分，正好对齐4字节)
        memcpy(&send_buffer[sizeof(struct EthernetHeader)], &ip, 20);
        //!SECTION

        // SECTION - 填充TCP报文
        /* --------------------------------- 填充TCP报文 -------------------------------- */
        // 赋值TCP首部
        tcp.dest_port = htons(DEST_PORT);
        tcp.src_port = htons(SRC_PORT);
        tcp.sequence_num = htonl(SEQ_NUM);
        tcp.acknowledgment = ACK_NUM;
        tcp.hdr_len = 0x50; //TODO - 这里不需要转化为网络字节序吗
        tcp.flags = 0x18; // 0 1 0 0 1 0 
        tcp.advertised_window = htons(512);
        tcp.urg_ptr = 0;//不使用URG，因此不用紧急指针
        tcp.check_sum = 0; //先放全0
        // 赋值SendBuffer
        memcpy(&send_buffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
        // 赋值伪首部
        ptcp.source_addr = ip.ip_souce_address;
        ptcp.destination_addr = ip.ip_destination_address;
        ptcp.zero = 0;
        ptcp.protcol = TCP_PROTOCOL;
        ptcp.tcp_len = htons(sizeof(struct TcpHeader) + strlen(tcp_data));
        // 声明临时存储变量，用来计算校验和
        char temp_buffer[MTU_SIZE];
        memcpy(temp_buffer, &ptcp, sizeof(struct PsdTcpHeader));
        memcpy(temp_buffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
        memcpy(temp_buffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), tcp_data, strlen(tcp_data));
        // 计算TCP的校验和
        tcp.check_sum = checksum((USHORT*)(temp_buffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(tcp_data));
        // 重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
        memcpy(send_buffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
        memcpy(send_buffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), tcp_data, strlen(tcp_data));
        // 初始化TempBuffer为0序列，存储变量来计算IP校验和
        memset(temp_buffer, 0, sizeof(temp_buffer));
        memcpy(temp_buffer, &ip, sizeof(struct IpHeader));
        // 计算IP校验和
        ip.ip_checksum = checksum((USHORT*)(temp_buffer), sizeof(struct IpHeader));
        // 重新把SendBuffer赋值，IP校验和已经改变
        memcpy(send_buffer + sizeof(struct EthernetHeader), &ip, sizeof(struct IpHeader));
        // 发送序列的长度
        int size = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(tcp_data);
        int result = pcap_sendpacket(adhandle, send_buffer, size);
        if (result != 0) {
            printf("=>发送失败!\n");
        } else {
            printf("=>发送TCP数据包.\n");
            printf("目的端口:%d\n", ntohs(tcp.dest_port));
            printf("源端口:%d\n", ntohs(tcp.src_port));
            printf("序号:%d\n", ntohl(tcp.sequence_num));
            printf("确认号:%d\n", ntohl(tcp.acknowledgment));
            printf("首部长度:%d*4\n", tcp.hdr_len >> 4);
            printf("标志位:0x%0x\n", ntohs(tcp.flags));
            printf("窗口大小:%d\n", ntohs(tcp.advertised_window));
            printf("紧急指针:%d\n", ntohs(tcp.urg_ptr));
            printf("检验和:%u\n", ntohs(tcp.check_sum));
            printf("=>发送成功!\n");
        }
        free(tcp_data);
    }
    return 0;
}

/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) {
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
    EthernetHeader eh;
    ArpFrame ah;
    
    //ANCHOR - 赋值MAC地址
    memset(eh.dest_mac, 0xff, 6);  // 目的地址为全为广播地址
    memcpy(eh.source_mac, mac, 6);
    eh.ether_type = htons(ETH_ARP);

    memcpy(ah.source_mac_addr, mac, 6);
    memset(ah.dest_mac_addr, 0x00, 6);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_addr_len = 6;
    ah.protocol_addr_len = 4;
    ah.source_ip_addr = inet_addr(ip);  // 请求方的IP地址为自身的IP地址
    ah.operation_field = htons(ARP_REQUEST);
    // 向局域网内广播发送arp包
    u_long myip = inet_addr(ip);
    u_long mynetmask = inet_addr(netmask);
    u_long hisip = htonl((myip & mynetmask));
    // 向255个主机发送
    for (int i = 0; i < HOST_NUM; i++) {
        ah.dest_ip_addr = htonl(hisip + i);
        // 构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));

        pcap_sendpacket(adhandle, sendbuf, 42); //发送填入自己MAC地址的ARP报文
        //  如果发送成功
        /*if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
            printf("\n成功发送ARP请求分组\n");
        } else {
            printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        }*/
        Sleep(50);
    }
    Sleep(1000);
    flag = TRUE;
    return 0;
}

/* 分析截留的数据包获取活动的主机IP地址 */
DWORD WINAPI GetLivePC(LPVOID lpParameter) {
    GetParam* gpara = (GetParam*)lpParameter;
    pcap_t* adhandle = gpara->adhandle;
    int res;
    u_char Mac[6];
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    while (true) {
        if (flag) {
            printf("获取MAC地址完毕,请输入你要发送对方的IP地址:\n");
            break;
        }
        if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
            if (*(u_short*)(pkt_data + 12) == htons(ETH_ARP)) {
                ArpPacket* recv = (ArpPacket*)pkt_data;
                if (*(u_short*)(pkt_data + 20) == htons(ARP_REPLY)) {
                    printf("-------------------------------------------\n");
                    printf("IP地址:%d.%d.%d.%d   MAC地址:",
                           recv->ah.source_ip_addr & 255,
                           recv->ah.source_ip_addr >> 8 & 255,
                           recv->ah.source_ip_addr >> 16 & 255,
                           recv->ah.source_ip_addr >> 24 & 255);
                    for (int i = 0; i < 6; i++) {
                        if (0 < i && i < 6) printf("-");
                        Mac[i] = *(u_char*)(pkt_data + 22 + i);
                        printf("%02X", Mac[i]);
                    }
                    printf("\n");
                }
            }
        }
        Sleep(10);
    }
    return 0;
}

// 获取IP和子网掩码并赋值为ip_addr和ip_netmask
void thread_getIP(pcap_if_t* d, char* ip_addr, char* ip_netmask) {
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
int thread_getSelfMAC(pcap_t* adhandle, const char* ip_addr, u_char* ip_mac) {
    u_char sendbuf[ARP_PKT_LEN];  // arp包结构大小 arp报文总共42 bytes。其中以太网首部14bytes，arp字段28字节
    int i = -1;
    int res;
    EthernetHeader eh;  // 以太网帧头
    ArpFrame ah;        // ARP帧头
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    memset(eh.dest_mac, 0xff, 6);  // 目的地址为全1为广播地址
    memset(eh.source_mac, 0x0f, 6);  // 以太网源地址
    // htons将一个无符号短整型的主机数值转换为网络字节顺序
    eh.ether_type = htons(ETH_ARP);
    
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_addr_len = 6;
    ah.protocol_addr_len = 4;
    ah.operation_field = htons(ARP_REQUEST);
    memset(ah.source_mac_addr, 0x00, 6);               // 发送者MAC地址
    ah.source_ip_addr = inet_addr("100.100.100.100");  // 随便设的请求方ip
    memset(ah.dest_mac_addr, 0x0f, 6);                 // 目的MAC地址
    ah.dest_ip_addr = inet_addr(ip_addr);

    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    printf("发送的ARP广播分组：%s", sendbuf);

    pcap_sendpacket(adhandle, sendbuf, ARP_PKT_LEN);
    /*if (pcap_sendpacket(adhandle, sendbuf, ARP_PKT_LEN) == 0) {
        printf("\n成功发送ARP广播分组\n");
    }
    else {
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