// 捕获网络数据包的C++程序
// 可以获得数据包长度、通过以太网类型确定上层协议、源以太网地址和目的以太网地址！
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include "flow_dump.h"
#include "utils.h"

//std::unordered_map<std::string, int> dumpMsg;
//std::ofstream ofs;

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    int inum;
    //int pktnum;
    //pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    //u_int netmask = 0xffffff;
    //struct bpf_program fcode;
    //std::string rule = "ip or arp";

    /*取得列表*/
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("获取列表失败！\n");
        exit(1);
    }

    GetMenu(alldevs);

    ///*输出列表*/
    //for (d = alldevs; d != NULL; d = d->next) {
    //    ifprint(d, i);
    //}
    //if (i == 0) {
    //    printf("\n没有找到接口!确保安装了WinPcap.\n");
    //    //getchar();
    //    return -1;
    //}
    //printf("选择一个适配器(1~%d):", i);
    //scanf("%d", &inum);
    //if (inum < 1 || inum > i) {
    //    printf("输入的序号超出范围！\n");
    //    pcap_freealldevs(alldevs);
    //    //getchar();
    //    return -1;
    //}

    //// 转到选择的设备
    //for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    //    ;
    //// 打开失败
    //if ((adhandle = pcap_open_live(d->name, MTU_SIZE, 1, TIME_OUT, errbuf)) == NULL) {
    //    fprintf(stderr, "\n无法打开适配器，Winpcap不支持 %s\n", d->name);
    //    pcap_freealldevs(alldevs);
    //    //getchar();
    //    return -1;
    //}

    //// 释放设备列表
    //pcap_freealldevs(alldevs);

    ////设置过滤规则引擎
    //std::string src_ip, dst_port;
    //printf("=====设置过滤规则(d表示默认全部监听)=====\n");
    //printf("请输入需要监听的主机的IP地址和该主机上的端口号：\n");
    //std::cin >> src_ip >> dst_port;//src host 10.51.123.13 && dst port 102
    //if(src_ip != "d" && dst_port != "d") {
    //    rule = "src host " + src_ip + " && dst port " + dst_port;
    //}
    //if (pcap_compile(adhandle, &fcode, rule.c_str(), 1, netmask) < 0) {
    //    fprintf(stderr, "\n无法编译包过滤器。请检查BPF语法。\n");
    //    pcap_close(adhandle);
    //    return -1;
    //}

    ////启用过滤规则引擎
    //if (pcap_setfilter(adhandle, &fcode) < 0) {
    //    fprintf(stderr, "\n设置过滤器错误。\n");
    //    pcap_close(adhandle);
    //    return -1;
    //}

    //printf("请输入你想要捕获的数据包数量(0表示持续捕获): \n");
    //scanf("%d", &pktnum);

    //// 开始捕捉
    //std::cout << "当前过滤规则是: " + rule << std::endl;
    //printf("\n监听网卡: %s ...\n", d->description);

    ////ofs.open("getLog.txt", std::ios::out | std::ios::trunc);
    //pcap_loop(adhandle, pktnum, packet_handler, NULL);
    //
    //pcap_close(adhandle);
    ////ofs.close();
    //getchar();
    return 0;
}

/* Callback function invoked by npcap for every incoming packet */
//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    struct tm* ltime;
//    char timestr[16];
//    time_t local_tv_sec;
//    /* convert the timestamp to readable format */
//    local_tv_sec = header->ts.tv_sec;
//    ltime = localtime(&local_tv_sec);
//    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//    std::cout << B_DIVISION << "时间戳:" << timestr << ","
//        << header->ts.tv_usec << "  长度:" << header->len << B_DIVISION << std::endl;
//    ethernet_package_handler(param, header, pkt_data); // 先从以太网MAC帧开始
//}
//
//void ethernet_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    ethernet_header* eh = (ethernet_header*)pkt_data;
//    std::cout << DIVISION << "以太网协议分析结构" << DIVISION << std::endl;
//    u_short type = ntohs(eh->type);
//    std::cout << "类型：0x" << std::hex << type;
//    std::cout << std::setbase(10);
//    switch (type) {
//    case ETH_IPV4:
//        std::cout << " (IPv4)" << std::endl;
//        break;
//    case ETH_IPV6:
//        std::cout << "(IPv6)" << std::endl;
//        break;
//    case ETH_ARP:
//        std::cout << " (ARP)" << std::endl;
//        break;
//    case ETH_RARP:
//        std::cout << " (RARP)" << std::endl;
//    default:
//        break;
//    }
//    std::cout << "目的地址：" << int(eh->des_mac_addr.byte1) << ":"
//        << int(eh->des_mac_addr.byte2) << ":"
//        << int(eh->des_mac_addr.byte3) << ":"
//        << int(eh->des_mac_addr.byte4) << ":"
//        << int(eh->des_mac_addr.byte5) << ":"
//        << int(eh->des_mac_addr.byte6) << std::endl;
//    std::cout << "源地址：" << int(eh->src_mac_addr.byte1) << ":"
//        << int(eh->src_mac_addr.byte2) << ":"
//        << int(eh->src_mac_addr.byte3) << ":"
//        << int(eh->src_mac_addr.byte4) << ":"
//        << int(eh->src_mac_addr.byte5) << ":"
//        << int(eh->src_mac_addr.byte6) << std::endl;
//    switch (type) {
//    case ETH_IPV4:
//        ip_v4_package_handler(param, header, pkt_data);
//        break;
//    case ETH_ARP:
//        arp_package_handler(param, header, pkt_data);
//        break;
//    case ETH_IPV6:
//        ip_v6_package_handler(param, header, pkt_data);
//        break;
//    default:
//        break;
//    }
//    std::cout << std::endl
//        << std::endl;
//}
//
//void arp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    arp_header* ah;
//    ah = (arp_header*)(pkt_data + 14);
//    std::cout << DIVISION << "ARP协议分析结构" << DIVISION << std::endl;
//    u_short operation_code = ntohs(ah->operation_code);
//    std::cout << "硬件类型：" << ntohs(ah->hardware_type) << std::endl;
//    std::cout << "协议类型：0x" << std::hex << ntohs(ah->protocol_type) << std::endl;
//    std::cout << std::setbase(10);
//    std::cout << "硬件地址长度：" << int(ah->hardware_length) << std::endl;
//    std::cout << "协议地址长度：" << int(ah->protocol_length) << std::endl;
//    switch (operation_code) {
//    case 1:
//        std::cout << "ARP请求协议" << std::endl;
//        break;
//    case 2:
//        std::cout << "ARP应答协议" << std::endl;
//        break;
//    case 3:
//        std::cout << "ARP请求协议" << std::endl;
//        break;
//    case 4:
//        std::cout << "RARP应答协议" << std::endl;
//        break;
//    default:
//        break;
//    }
//    std::cout << "源IP地址："
//        << int(ah->src_ip_addr.dot_fmt.byte1) << "."
//        << int(ah->src_ip_addr.dot_fmt.byte2) << "."
//        << int(ah->src_ip_addr.dot_fmt.byte3) << "."
//        << int(ah->src_ip_addr.dot_fmt.byte4) << std::endl;
//
//    std::cout << "目的IP地址："
//        << int(ah->des_ip_addr.dot_fmt.byte1) << "."
//        << int(ah->des_ip_addr.dot_fmt.byte2) << "."
//        << int(ah->des_ip_addr.dot_fmt.byte3) << "."
//        << int(ah->des_ip_addr.dot_fmt.byte4) << std::endl;
//
//    add_to_map(dumpMsg, ah->src_ip_addr);
//    print_map(dumpMsg);
//}
//
//void ip_v4_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    ipv4_header* ih;
//    ih = (ipv4_header*)(pkt_data + 14);  // 14 measn the length of ethernet header
//    std::cout << DIVISION << "IPv4协议分析结构" << DIVISION << std::endl;
//    std::cout << "版本号：" << ((ih->ver_hlen & 0xf0) >> 4) << std::endl;
//    std::cout << "首部长度：" << (ih->ver_hlen & 0xf) << "("
//        << ((ih->ver_hlen & 0xf) << 2) << "B)" << std::endl;
//    std::cout << "区别服务：" << int(ih->tos) << std::endl;
//    std::cout << "总长度：" << ntohs(ih->tlen) << std::endl;
//    std::cout << "标识：" << ntohs(ih->id) << std::endl;
//    std::cout << "标志：" << ((ih->flags_offset & 0xE000) >> 12) << std::endl;
//    std::cout << "片偏移：" << (ih->flags_offset & 0x1FFF) << "("
//        << ((ih->flags_offset & 0x1FFF) << 3) << "B)" << std::endl;
//    std::cout << "生命周期：" << int(ih->ttl) << std::endl;
//    std::cout << "协议：";
//    switch (ih->protocol) {
//    case 6:
//        std::cout << "TCP" << std::endl;
//        break;
//    case 17:
//        std::cout << "UDP" << std::endl;
//        break;
//    case 1:
//        std::cout << "ICMP" << std::endl;
//        break;
//    default:
//        std::cout << std::endl;
//        break;
//    }
//    std::cout << "校验和：" << ntohs(ih->checksum) << std::endl;
//    std::cout << "源IP地址："
//        << int(ih->src_ip_addr.dot_fmt.byte1) << "."
//        << int(ih->src_ip_addr.dot_fmt.byte2) << "."
//        << int(ih->src_ip_addr.dot_fmt.byte3) << "."
//        << int(ih->src_ip_addr.dot_fmt.byte4) << std::endl;
//                               
//    std::cout << "目的IP地址：" 
//        << int(ih->des_ip_addr.dot_fmt.byte1) << "."
//        << int(ih->des_ip_addr.dot_fmt.byte2) << "."
//        << int(ih->des_ip_addr.dot_fmt.byte3) << "."
//        << int(ih->des_ip_addr.dot_fmt.byte4) << std::endl;
//    switch (ih->protocol) {
//    case IP_TCP:
//        tcp_package_handler(param, header, pkt_data);
//        break;
//    case IP_UDP:
//        udp_package_handler(param, header, pkt_data);
//        break;
//    case IP_ICMPV4:
//        icmp_package_handler(param, header, pkt_data);
//        break;
//    default:
//        break;
//    }
//    add_to_map(dumpMsg, ih->src_ip_addr);
//    print_map(dumpMsg);
//}
//
//void ip_v6_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    ipv6_header* ih;
//    ih = (ipv6_header*)(pkt_data + 14);  // 14 measn the length of ethernet header
//    int version = (ih->ver_trafficclass_flowlabel & 0xf0000000) >> 28;
//    int traffic_class = ntohs((ih->ver_trafficclass_flowlabel & 0x0ff00000) >> 20);
//    int flow_label = ih->ver_trafficclass_flowlabel & 0x000fffff;
//    std::cout << "版本号：" << version << std::endl;
//    std::cout << "通信量类：" << traffic_class << std::endl;
//    std::cout << "流标号：" << flow_label << std::endl;
//    std::cout << "有效载荷：" << ntohs(ih->payload_len) << std::endl;
//    std::cout << "下一个首部：" << int(ih->next_head) << std::endl;
//    std::cout << "跳数限制：" << int(ih->ttl) << std::endl;
//    std::cout << "源IP地址："
//        << int(ih->src_ip_addr.part1) << ":"
//        << int(ih->src_ip_addr.part2) << ":"
//        << int(ih->src_ip_addr.part3) << ":"
//        << int(ih->src_ip_addr.part4) << ":"
//        << int(ih->src_ip_addr.part5) << ":"
//        << int(ih->src_ip_addr.part6) << ":"
//        << int(ih->src_ip_addr.part7) << ":"
//        << int(ih->src_ip_addr.part8) << std::endl;
//    std::cout << "目的IP地址："
//        << int(ih->dst_ip_addr.part1) << ":"
//        << int(ih->dst_ip_addr.part2) << ":"
//        << int(ih->dst_ip_addr.part3) << ":"
//        << int(ih->dst_ip_addr.part4) << ":"
//        << int(ih->dst_ip_addr.part5) << ":"
//        << int(ih->dst_ip_addr.part6) << ":"
//        << int(ih->dst_ip_addr.part7) << ":"
//        << int(ih->dst_ip_addr.part8) << std::endl;
//    switch (ih->next_head) {
//    case IP_TCP:
//        tcp_package_handler(param, header, pkt_data);
//        break;
//    case IP_UDP:
//        udp_package_handler(param, header, pkt_data);
//        break;
//    case IP_ICMPV6:
//        icmp_package_handler(param, header, pkt_data);
//        break;
//    default:
//        break;
//    }
//    add_to_map(dumpMsg, ih->src_ip_addr);
//    print_map(dumpMsg);
//}
//
//void udp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    udp_header* uh;
//    uh = (udp_header*)(pkt_data + 20 + 14);
//    std::cout << DIVISION << "UDP协议分析结构" << DIVISION << std::endl;
//    std::cout << "源端口：" << ntohs(uh->sport) << std::endl;
//    std::cout << "目的端口：" << ntohs(uh->dport) << std::endl;
//    std::cout << "长度：" << ntohs(uh->len) << std::endl;
//    std::cout << "检验和：" << ntohs(uh->checksum) << std::endl;
//}
//
//void tcp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    tcp_header* th;
//    th = (tcp_header*)(pkt_data + 14 + 20);
//    char* data = (char*)((u_char*)th + 20);
//    std::cout << DIVISION << "TCP协议分析结构" << DIVISION << std::endl;
//    std::cout << "源端口：" << ntohs(th->sport) << std::endl;
//    std::cout << "目的端口：" << ntohs(th->dport) << std::endl;
//    std::cout << "序号：" << ntohl(th->seq) << std::endl;
//    std::cout << "确认号：" << ntohl(th->ack) << std::endl;
//    std::cout << "数据偏移：" << ((th->offset & 0xf0) >> 4) << "("
//        << ((th->offset & 0xf0) >> 2) << "B)" << std::endl;
//    std::cout << "标志：";
//    if (th->flags & 0x01) {
//        std::cout << "FIN ";
//    }
//    if (th->flags & 0x02) {
//        std::cout << "SYN ";
//    }
//    if (th->flags & 0x04) {
//        std::cout << "RST ";
//    }
//    if (th->flags & 0x08) {
//        std::cout << "PSH ";
//    }
//    if (th->flags & 0x10) {
//        std::cout << "ACK ";
//    }
//    if (th->flags & 0x20) {
//        std::cout << "URG ";
//    }
//    std::cout << std::endl;
//    std::cout << "窗口：" << ntohs(th->window) << std::endl;
//    std::cout << "检验和：" << ntohs(th->checksum) << std::endl;
//    std::cout << "紧急指针：" << ntohs(th->urg) << std::endl;
//    std::cout << "数据部分：" << data << std::endl;
//}
//
//void icmp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
//    icmp_header* ih;
//    ih = (icmp_header*)(pkt_data + 14 + 20);
//    std::cout << DIVISION << "ICMP协议分析结构" << DIVISION << std::endl;
//    std::cout << "ICMP类型：" << ih->type;
//    switch (ih->type) {
//    case 8:
//        std::cout << "ICMP回显请求协议" << std::endl;
//        break;
//    case 0:
//        std::cout << "ICMP回显应答协议" << std::endl;
//        break;
//    default:
//        break;
//    }
//    std::cout << "ICMP代码：" << ih->code << std::endl;
//    std::cout << "标识符：" << ih->id << std::endl;
//    std::cout << "序列码：" << ih->sequence << std::endl;
//    std::cout << "ICMP校验和：" << ntohs(ih->checksum) << std::endl;
//}
//
//void add_to_map(std::unordered_map<std::string, int>& dump, ipv4_address ip) {
//    std::string ip_string;
//    int amount = 0;
//    std::unordered_map<std::string, int>::iterator iter;
//    ip_string = std::to_string(ip.dot_fmt.byte1) + "." + std::to_string(ip.dot_fmt.byte2) + "." + std::to_string(ip.dot_fmt.byte3) + "." + std::to_string(ip.dot_fmt.byte4);
//    iter = dump.find(ip_string);
//    if (iter != dump.end()) {
//        amount = iter->second;
//    }
//    dump.insert_or_assign(ip_string, ++amount);
//}
//
//void add_to_map(std::unordered_map<std::string, int>& dump, ipv6_address ip) {
//    std::string ip_string;
//    int amount = 0;
//    std::unordered_map<std::string, int>::iterator iter;
//    ip_string = std::to_string(ip.part1) + ":" + std::to_string(ip.part2) + ":" + std::to_string(ip.part3) + ":" + std::to_string(ip.part4) + ":" + std::to_string(ip.part5) + ":" + std::to_string(ip.part6) + ":" + std::to_string(ip.part7) + ":" + std::to_string(ip.part8);
//    iter = dump.find(ip_string);
//    if (iter != dump.end()) {
//        amount = iter->second;
//    }
//    dump.insert_or_assign(ip_string, ++amount);
//}
//
//void print_map(std::unordered_map<std::string, int> dump) {
//    std::ofstream ofs_flow;
//    ofs_flow.open("flowDump.txt", std::ios::out | std::ios::trunc );
//    std::unordered_map<std::string, int>::iterator iter;
//    std::cout << DIVISION << "流量统计" << DIVISION << std::endl;
//    ofs_flow << DIVISION << "流量统计" << DIVISION << std::endl;
//    std::cout << "IP" << std::setfill(' ') << std::setw(45) << "流量" << std::endl;
//    ofs_flow << "IP" << std::setfill(' ') << std::setw(45) << "流量" << std::endl;
//    for (iter = dump.begin(); iter != dump.end(); iter++) {
//        std::cout << iter->first << std::setfill('.') << std::setw(45 - iter->first.length()) << iter->second << std::endl;
//        ofs_flow << iter->first << std::setfill('.') << std::setw(45 - iter->first.length()) << iter->second << std::endl;
//    }
//    ofs_flow.close();
//}