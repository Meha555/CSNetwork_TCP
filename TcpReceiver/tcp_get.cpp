// 捕获网络数据包的C++程序
// 可以获得数据包长度、通过以太网类型确定上层协议、源以太网地址和目的以太网地址！
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include <time.h>
#include <winsock2.h>
#include "pcap.h"

//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data);
#define IPTOSBUFFERS 12
void ifprint(pcap_if_t* d);
char* iptos(u_long in);
int i = 0;
/*以下是以太网协议格式*/
struct ether_header {
    uint8_t ether_dhost[6];  // 目的Mac地址
    uint8_t ether_shost[6];  // 源Mac地址
    uint16_t ether_type;     // 协议类型
};

struct ip_header {
    unsigned char Version_HLen;  // 版本信息4位 ，头长度4位 1字节
    uint8_t ip_tos;
    uint16_t ip_length;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint16_t ip_checksum;
    struct in_addr ip_souce_address;
    struct in_addr ip_destination_address;
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

void ip_protool_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    struct ip_header* ip_protocol;
    u_int header_length = 0;
    u_int offset;
    u_char tos;
    uint16_t checksum;
    u_int ip_len;  // ip首部长度
    u_int ip_version;
    TcpHeader* tcp;  // TCP头
    u_short sport, dport;
    // MAC首部是14位的，加上14位得到IP协议首部
    ip_protocol = (struct ip_header*)(packet_content + 14);

    ip_len = (ip_protocol->Version_HLen & 0xf) * 4;
    ip_version = ip_protocol->Version_HLen >> 4;
    tcp = (TcpHeader*)((u_char*)ip_protocol + ip_len);

    checksum = ntohs(ip_protocol->ip_checksum);
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    /*将if判断去掉，即可接受所有TCP数据包 */
    if (*(unsigned long*)(packet_content + 30) == inet_addr("192.168.3.4")) {  // 如果接收端ip地址为192.168.3.4
        printf("---------IP协议---------\n");
        printf("版本号:%d\n", ip_version);
        printf("首部长度:%d\n", ip_len);
        printf("服务质量:%d\n", tos);
        printf("总长度:%d\n", ntohs(ip_protocol->ip_length));
        printf("标识:%d\n", ntohs(ip_protocol->ip_id));
        printf("偏移:%d\n", (offset & 0x1fff) * 8);
        printf("生存时间:%d\n", ip_protocol->ip_ttl);
        printf("协议类型:%d\n", ip_protocol->ip_protocol);
        switch (ip_protocol->ip_protocol) {
            case 1:
                printf("上层协议是ICMP协议\n");
                break;
            case 2:
                printf("上层协议是IGMP协议\n");
                break;
            case 6:
                printf("上层协议是TCP协议\n");
                break;
            case 17:
                printf("上层协议是UDP协议\n");
                break;
            default:
                break;
        }

        printf("检验和:%d\n", checksum);
        printf("源IP地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
        printf("目的地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));

        // 将网络字节序列转换成主机字节序列
        printf("---------TCP协议---------\n");
        sport = ntohs(tcp->SrcPort);
        dport = ntohs(tcp->DstPort);
        printf("源端口:%d 目的端口:%d\n", sport, dport);
        printf("序号:%d\n", ntohl(tcp->SequenceNum));
        printf("确认号:%d\n", ntohl(tcp->Acknowledgment));
        printf("偏移地址（首部长度）:%d\n", (tcp->HdrLen >> 4) * 4);
        printf("标志位:%d\n", tcp->Flags);
        printf("紧急UGR:%d\n", (tcp->Flags & 0x20) / 32);
        printf("确认ACK:%d\n", (tcp->Flags & 0x10) / 16);
        printf("推送PSH:%d\n", (tcp->Flags & 0x08) / 8);
        printf("复位RST:%d\n", (tcp->Flags & 0x04) / 4);
        printf("同步SYN:%d\n", (tcp->Flags & 0x02) / 2);
        printf("终止FIN:%d\n", tcp->Flags & 0x01);
        printf("窗口大小:%d\n", ntohs(tcp->AdvertisedWindow));
        printf("校验和:%d\n", ntohs(tcp->Checksum));
        printf("紧急指针:%d\n", ntohs(tcp->UrgPtr));
        char* data;
        data = (char*)((u_char*)tcp + 20);
        printf("---------数据部分---------\n");
        printf("数据部分:%s\n", data);
    }
}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    u_short ethernet_type;
    struct ether_header* ethernet_protocol;
    u_char* mac_string;
    static int packet_number = 1;

    ethernet_protocol = (struct ether_header*)packet_content;  // 获得数据包内容
    ethernet_type = ntohs(ethernet_protocol->ether_type);      // 获得以太网类型
    if (ethernet_type == 0x0800)                               // 继续分析IP协议
    {
        ip_protool_packet_callback(argument, packet_header, packet_content);
    }

    packet_number++;
}

int main()
// {
//      pcap_t* pcap_handle; //winpcap句柄
//      char error_content[PCAP_ERRBUF_SIZE]; //存储错误信息
//      bpf_u_int32 net_mask; //掩码地址
//      bpf_u_int32 net_ip;  //网络地址
//      char *net_interface;  //网络接口
//      struct bpf_program bpf_filter;  //BPF过滤规则
//      char bpf_filter_string[]="ip"; //过滤规则字符串，只分析IPv4的数据包
//      net_interface=pcap_lookupdev(error_content); //获得网络接口
//      pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content); //获得网络地址和掩码地址
//      pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content); //打开网络接口
//      pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,net_ip); //编译过滤规则
//      pcap_setfilter(pcap_handle,&bpf_filter);//设置过滤规则
//      if (pcap_datalink(pcap_handle)!=DLT_EN10MB) //DLT_EN10MB表示以太网
//          return 0;
//      pcap_loop(pcap_handle,10,ethernet_protocol_packet_callback,NULL); //捕获10个数据包进行分析
//      pcap_close(pcap_handle);
//      return 0;
// }
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    /*取得列表*/
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        exit(1);
    }
    /*输出列表*/
    for (d = alldevs; d != NULL; d = d->next) {
        ifprint(d);
    }
    if (i == 0) {
        printf("\nNo interfaces found!Make sure WinPcap is installed.\n");
        char c = getchar();
        return -1;
    }
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        char c = getchar();
        return -1;
    }

    // 转到选择的设备
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ;
    // 打开失败
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter.%s is not supported by WinPcap\n");
        pcap_freealldevs(alldevs);
        char c = getchar();
        return -1;
    }
    printf("\nlistening on %s...\n", d->description);
    // 释放列表
    pcap_freealldevs(alldevs);
    // 开始捕捉
    // pcap_loop(adhandle,0,ip_protool_packet_callback,NULL);
    pcap_loop(adhandle, 0, ethernet_protocol_packet_callback, NULL);
    char c = getchar();
    return 0;
}
void ifprint(pcap_if_t* d) {
    pcap_addr_t* a;
    printf("%d.%s", ++i, d->name);
    if (d->description) {
        printf("\tDescription:(%s)\n", d->description);
    } else {
        printf("\t(No description available)\n");
    }
    printf("\tLoopback:%s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
    for (a = d->addresses; a != NULL; a = a->next) {
        printf("\tAddress Family:#%d\n", a->addr->sa_family);
        switch (a->addr->sa_family) {
            case AF_INET:
                printf("\tAddress Family Name:AF_INET\n");
                if (a->addr) {
                    printf("\tAddress:%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                }
                if (a->netmask) {
                    printf("\tNetmask:%s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                }
                if (a->broadaddr) {
                    printf("\tBroadcast Address:%s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                }
                if (a->dstaddr) {
                    printf("\tDestination Address:%s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                }
                break;
            default:
                printf("\tAddressFamilyName:Unknown\n");
                break;
        }
    }
}
char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;
    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data) {
    struct tm* ltime;
    char timestr[16];
    time_t temp = header->ts.tv_sec;
    ltime = localtime(&temp);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}
