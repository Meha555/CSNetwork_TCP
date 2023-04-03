// 捕获网络数据包的C++程序
// 可以获得数据包长度、通过以太网类型确定上层协议、源以太网地址和目的以太网地址！
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include <pcap.h>
#include <winsock2.h>
#include <stdio.h>
#include "net-types.h"
#include "utils.h"

//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data);
void ifprint(pcap_if_t* dev, int& i);
char* iptos(u_long in);

int i = 0;

void ip_protool_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    struct IpHeader* ip_protocol;
    u_int header_length = 0;
    u_int offset;
    u_char tos;
    uint16_t checksum;
    u_int ip_len;  // ip首部长度
    u_int ip_version;
    TcpHeader* tcp;  // TCP头
    u_short sport, dport;
    // MAC首部是14位的，加上14位得到IP协议首部
    ip_protocol = (struct IpHeader*)(packet_content + 14);

    ip_len = (ip_protocol->Version_HLen & 0xf) * 4;
    ip_version = ip_protocol->Version_HLen >> 4;
    tcp = (TcpHeader*)((u_char*)ip_protocol + ip_len);

    checksum = ntohs(ip_protocol->ip_checksum);
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_flag_off);
    /*将if判断去掉，即可接受所有TCP数据包 */
    if (*(u_long*)(packet_content + 30) == inet_addr("192.168.43.208")) {  // 如果接收端ip地址为192.168.3.4
        FILE* file_text_write = fopen("getLog.txt", "a");
        fprintf(file_text_write, "---------IP协议---------\n");
        fprintf(file_text_write, "版本号:%d\n", ip_version);
        fprintf(file_text_write, "首部长度:%d\n", ip_len);
        fprintf(file_text_write, "服务质量:%d\n", tos);
        fprintf(file_text_write, "总长度:%d\n", ntohs(ip_protocol->ip_length));
        fprintf(file_text_write, "标识:%d\n", ntohs(ip_protocol->ip_id));
        fprintf(file_text_write, "偏移:%d\n", (offset & 0x1fff) * 8);
        fprintf(file_text_write, "生存时间:%d\n", ip_protocol->ip_ttl);
        fprintf(file_text_write, "协议类型:%d\n", ip_protocol->ip_protocol);
        switch (ip_protocol->ip_protocol)
        {
        case 1: fprintf(file_text_write, "上层协议是ICMP协议\n"); break;
        case 2: fprintf(file_text_write, "上层协议是IGMP协议\n"); break;
        case 6: fprintf(file_text_write, "上层协议是TCP协议\n"); break;
        case 17: fprintf(file_text_write, "上层协议是UDP协议\n"); break;
        default:break;
        }
        fprintf(file_text_write, "检验和:%d\n", checksum);
        fprintf(file_text_write, "源IP地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
        fprintf(file_text_write, "目的地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));

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
        printf("标志位:%d\n", ntohs(tcp->Flags));
        printf("紧急UGR:%d\n", (ntohs(tcp->Flags) & 0x20) / 32);
        printf("确认ACK:%d\n", (ntohs(tcp->Flags) & 0x10) / 16);
        printf("推送PSH:%d\n", (ntohs(tcp->Flags) & 0x08) / 8);
        printf("复位RST:%d\n", (ntohs(tcp->Flags) & 0x04) / 4);
        printf("同步SYN:%d\n", (ntohs(tcp->Flags) & 0x02) / 2);
        printf("终止FIN:%d\n", ntohs(tcp->Flags) & 0x01);
        printf("窗口大小:%d\n", ntohs(tcp->AdvertisedWindow));
        printf("校验和:%d\n", ntohs(tcp->Checksum));
        printf("紧急指针:%d\n", ntohs(tcp->UrgPtr));
        char* data;
        data = (char*)((u_char*)tcp + 20);//data是否存在网络字节序的问题？
        printf("---------数据部分---------\n");
        printf("数据部分:%s\n", data);

        fprintf(file_text_write, "---------TCP协议---------\n");
        fprintf(file_text_write, "源端口:%d 目的端口:%d\n", sport, dport);
        fprintf(file_text_write, "序号:%d\n", ntohl(tcp->SequenceNum));
        fprintf(file_text_write, "确认号:%d\n", ntohl(tcp->Acknowledgment));
        fprintf(file_text_write, "偏移地址（首部长度）:%d\n", (tcp->HdrLen >> 4) * 4);
        fprintf(file_text_write, "标志位:%d\n", ntohs(tcp->Flags));
        fprintf(file_text_write, "紧急UGR:%d\n", (ntohs(tcp->Flags) & 0x20) / 32);
        fprintf(file_text_write, "确认ACK:%d\n", (ntohs(tcp->Flags) & 0x10) / 16);
        fprintf(file_text_write, "推送PSH:%d\n", (ntohs(tcp->Flags) & 0x08) / 8);
        fprintf(file_text_write, "复位RST:%d\n", (ntohs(tcp->Flags) & 0x04) / 4);
        fprintf(file_text_write, "同步SYN:%d\n", (ntohs(tcp->Flags) & 0x02) / 2);
        fprintf(file_text_write, "终止FIN:%d\n", ntohs(tcp->Flags) & 0x01);
        fprintf(file_text_write, "窗口大小:%d\n", ntohs(tcp->AdvertisedWindow));
        fprintf(file_text_write, "校验和:%d\n", ntohs(tcp->Checksum));
        fprintf(file_text_write, "紧急指针:%d\n", ntohs(tcp->UrgPtr));
        fprintf(file_text_write, "---------数据部分---------\n");
        fprintf(file_text_write, "数据部分:%s\n", data);
        fclose(file_text_write);
    }
}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    u_short ethernet_type;
    struct EthernetHeader* ethernet_protocol;
    u_char* mac_string;
    static int packet_number = 1;

    ethernet_protocol = (struct EthernetHeader*)packet_content;  // 获得数据包内容
    ethernet_type = ntohs(ethernet_protocol->EthType);      // 获得以太网类型
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
    FILE* file_text_write = fopen("getLog.txt", "w");
    fclose(file_text_write);
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int inum;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    /*取得列表*/
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        exit(1);
    }
    /*输出列表*/
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        ifprint(dev, i);
    }
    if (i == 0) {
        printf("\n没有找到接口!确保安装了WinPcap.\n");
        char c = getchar();
        return -1;
    }
    printf("选择一个适配器(1~%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("输入的序号超出范围！\n");
        pcap_freealldevs(alldevs);
        char c = getchar();
        return -1;
    }

    // 转到选择的设备
    for (dev = alldevs, i = 0; i < inum - 1; dev = dev->next, i++);

    // 打开失败
    if ((adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "\n无法打开适配器，Winpcap不支持 %s\n", dev->name);
        pcap_freealldevs(alldevs);
        char c = getchar();
        return -1;
    }
    printf("\n监听网卡: %s ...\n", dev->description);
    // 释放列表
    pcap_freealldevs(alldevs);
    // 开始捕捉
    // pcap_loop(adhandle,0,ip_protool_packet_callback,NULL);
    pcap_loop(adhandle, 0, ethernet_protocol_packet_callback, NULL);
    char c = getchar();
    return 0;
}