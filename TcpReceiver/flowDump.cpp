#include "flow_dump.h"

/*ip dumpMsg*/
std::map<std::string, int> dumpMsg;

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    int pktnum;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask = 0xffffff;
    struct bpf_program fcode;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        std::cout << ++i << "." << d->name;
        if (d->description)
            std::cout << d->description << std::endl;
        else
            std::cout << " (No description available)" << std::endl;
    }

    if (i == 0) {
        std::cout << "\nNo interfaces found! Make sure WinPcap is installed." << std::endl;
        return -1;
    }

    std::cout << "Enter the interface number (1-" << i << "): ";
    std::cin >> inum;

    if (inum < 1 || inum > i) {
        std::cout << "\nInterface number out of range." << std::endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open_live(d->name,  // name of the device
        65536,    // portion of the packet to capture.
        // 65536 grants that the whole packet will be captured on all the MACs.
        1,      // promiscuous mode (nonzero means promiscuous)
        1000,   // read timeout
        errbuf  // error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    std::cout << "listening on " << d->description << "...." << std::endl;

    pcap_freealldevs(alldevs);

    if (pcap_compile(adhandle, &fcode, "ip or arp", 1, netmask) < 0) {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_close(adhandle);
        return -1;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_close(adhandle);
        return -1;
    }

    std::cout << "please input the num of packets you want to catch(0 for keeping catching): ";
    std::cin >> pktnum;
    std::cout << std::endl;
    pcap_loop(adhandle, pktnum, packet_handler, NULL);
    pcap_close(adhandle);

    getchar();
    return 0;
}

/* Callback function invoked by npcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    std::cout << B_DIVISION << "time:" << timestr << ","
        << header->ts.tv_usec << "  len:" << header->len << B_DIVISION << std::endl;
    ethernet_package_handler(param, header, pkt_data);
}

void ethernet_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ethernet_header* eh = (ethernet_header*)pkt_data;
    std::cout << DIVISION << "��̫��Э������ṹ" << DIVISION << std::endl;
    u_short type = ntohs(eh->type);
    std::cout << "���ͣ�0x" << std::hex << type;
    std::cout << std::setbase(10);
    switch (type) {
    case 0x0800:
        std::cout << " (IPv4)" << std::endl;
        break;
    case 0x86DD:
        std::cout << "(IPv6)" << std::endl;
        break;
    case 0x0806:
        std::cout << " (ARP)" << std::endl;
        break;
    case 0x0835:
        std::cout << " (RARP)" << std::endl;
    default:
        break;
    }
    std::cout << "Ŀ�ĵ�ַ��" << int(eh->des_mac_addr.byte1) << ":"
        << int(eh->des_mac_addr.byte2) << ":"
        << int(eh->des_mac_addr.byte3) << ":"
        << int(eh->des_mac_addr.byte4) << ":"
        << int(eh->des_mac_addr.byte5) << ":"
        << int(eh->des_mac_addr.byte6) << std::endl;
    std::cout << "Դ��ַ��" << int(eh->src_mac_addr.byte1) << ":"
        << int(eh->src_mac_addr.byte2) << ":"
        << int(eh->src_mac_addr.byte3) << ":"
        << int(eh->src_mac_addr.byte4) << ":"
        << int(eh->src_mac_addr.byte5) << ":"
        << int(eh->src_mac_addr.byte6) << std::endl;
    switch (type) {
    case 0x0800:
        ip_v4_package_handler(param, header, pkt_data);
        break;
    case 0x0806:
        arp_package_handler(param, header, pkt_data);
        break;
    case 0x86DD:
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
    std::cout << DIVISION << "ARPЭ������ṹ" << DIVISION << std::endl;
    u_short operation_code = ntohs(ah->operation_code);
    std::cout << "Ӳ�����ͣ�" << ntohs(ah->hardware_type) << std::endl;
    std::cout << "Э�����ͣ�0x" << std::hex << ntohs(ah->protocol_type) << std::endl;
    std::cout << std::setbase(10);
    std::cout << "Ӳ����ַ���ȣ�" << int(ah->hardware_length) << std::endl;
    std::cout << "Э���ַ���ȣ�" << int(ah->protocol_length) << std::endl;
    switch (operation_code) {
    case 1:
        std::cout << "ARP����Э��" << std::endl;
        break;
    case 2:
        std::cout << "ARPӦ��Э��" << std::endl;
        break;
    case 3:
        std::cout << "ARP����Э��" << std::endl;
        break;
    case 4:
        std::cout << "RARPӦ��Э��" << std::endl;
        break;
    default:
        break;
    }
    std::cout << "ԴIP��ַ��"
        << int(ah->src_ip_addr.byte1) << "."
        << int(ah->src_ip_addr.byte2) << "."
        << int(ah->src_ip_addr.byte3) << "."
        << int(ah->src_ip_addr.byte4) << std::endl;

    std::cout << "Ŀ��IP��ַ��"
        << int(ah->des_ip_addr.byte1) << "."
        << int(ah->des_ip_addr.byte2) << "."
        << int(ah->des_ip_addr.byte3) << "."
        << int(ah->des_ip_addr.byte4) << std::endl;

    add_to_map(dumpMsg, ah->src_ip_addr);
    print_map(dumpMsg);
}

void ip_v4_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ipv4_header* ih;
    ih = (ipv4_header*)(pkt_data + 14);  // 14 measn the length of ethernet header
    std::cout << DIVISION << "IPv4Э������ṹ" << DIVISION << std::endl;
    std::cout << "�汾�ţ�" << ((ih->ver_hlen & 0xf0) >> 4) << std::endl;
    std::cout << "�ײ����ȣ�" << (ih->ver_hlen & 0xf) << "("
        << ((ih->ver_hlen & 0xf) << 2) << "B)" << std::endl;
    std::cout << "�������" << int(ih->tos) << std::endl;
    std::cout << "�ܳ��ȣ�" << ntohs(ih->tlen) << std::endl;
    std::cout << "��ʶ��" << ntohs(ih->id) << std::endl;
    std::cout << "��־��" << ((ih->flags_offset & 0xE000) >> 12) << std::endl;
    std::cout << "Ƭƫ�ƣ�" << (ih->flags_offset & 0x1FFF) << "("
        << ((ih->flags_offset & 0x1FFF) << 3) << "B)" << std::endl;
    std::cout << "�������ڣ�" << int(ih->ttl) << std::endl;
    std::cout << "Э�飺";
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
    std::cout << "У��ͣ�" << ntohs(ih->checksum) << std::endl;
    std::cout << "ԴIP��ַ��"
        << int(ih->src_ip_addr.byte1) << "."
        << int(ih->src_ip_addr.byte2) << "."
        << int(ih->src_ip_addr.byte3) << "."
        << int(ih->src_ip_addr.byte4) << std::endl;

    std::cout << "Ŀ��IP��ַ��"
        << int(ih->des_ip_addr.byte1) << "."
        << int(ih->des_ip_addr.byte2) << "."
        << int(ih->des_ip_addr.byte3) << "."
        << int(ih->des_ip_addr.byte4) << std::endl;
    switch (ih->protocol) {
    case 6:
        tcp_package_handler(param, header, pkt_data);
        break;
    case 17:
        udp_package_handler(param, header, pkt_data);
        break;
    case 1:
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
    std::cout << "�汾�ţ�" << version << std::endl;
    std::cout << "ͨ�����ࣺ" << traffic_class << std::endl;
    std::cout << "����ţ�" << flow_label << std::endl;
    std::cout << "��Ч�غɣ�" << ntohs(ih->payload_len) << std::endl;
    std::cout << "��һ���ײ���" << int(ih->next_head) << std::endl;
    std::cout << "�������ƣ�" << int(ih->ttl) << std::endl;
    std::cout << "ԴIP��ַ��"
        << int(ih->src_ip_addr.part1) << ":"
        << int(ih->src_ip_addr.part2) << ":"
        << int(ih->src_ip_addr.part3) << ":"
        << int(ih->src_ip_addr.part4) << ":"
        << int(ih->src_ip_addr.part5) << ":"
        << int(ih->src_ip_addr.part6) << ":"
        << int(ih->src_ip_addr.part7) << ":"
        << int(ih->src_ip_addr.part8) << std::endl;
    std::cout << "Ŀ��IP��ַ��"
        << int(ih->dst_ip_addr.part1) << ":"
        << int(ih->dst_ip_addr.part2) << ":"
        << int(ih->dst_ip_addr.part3) << ":"
        << int(ih->dst_ip_addr.part4) << ":"
        << int(ih->dst_ip_addr.part5) << ":"
        << int(ih->dst_ip_addr.part6) << ":"
        << int(ih->dst_ip_addr.part7) << ":"
        << int(ih->dst_ip_addr.part8) << std::endl;
    switch (ih->next_head) {
    case 6:
        tcp_package_handler(param, header, pkt_data);
        break;
    case 17:
        udp_package_handler(param, header, pkt_data);
        break;
    case 58:
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
    std::cout << DIVISION << "UDPЭ������ṹ" << DIVISION << std::endl;
    std::cout << "Դ�˿ڣ�" << ntohs(uh->sport) << std::endl;
    std::cout << "Ŀ�Ķ˿ڣ�" << ntohs(uh->dport) << std::endl;
    std::cout << "���ȣ�" << ntohs(uh->len) << std::endl;
    std::cout << "����ͣ�" << ntohs(uh->checksum) << std::endl;
}

void tcp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    tcp_header* th;
    th = (tcp_header*)(pkt_data + 14 + 20);
    std::cout << DIVISION << "TCPЭ������ṹ" << DIVISION << std::endl;
    std::cout << "Դ�˿ڣ�" << ntohs(th->sport) << std::endl;
    std::cout << "Ŀ�Ķ˿ڣ�" << ntohs(th->dport) << std::endl;
    std::cout << "��ţ�" << ntohl(th->seq) << std::endl;
    std::cout << "ȷ�Ϻţ�" << ntohl(th->ack) << std::endl;
    std::cout << "����ƫ�ƣ�" << ((th->offset & 0xf0) >> 4) << "("
        << ((th->offset & 0xf0) >> 2) << "B)" << std::endl;
    std::cout << "��־��";
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
    std::cout << "���ڣ�" << ntohs(th->window) << std::endl;
    std::cout << "����ͣ�" << ntohs(th->checksum) << std::endl;
    std::cout << "����ָ�룺" << ntohs(th->urg) << std::endl;
}

void icmp_package_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    icmp_header* ih;
    ih = (icmp_header*)(pkt_data + 14 + 20);
    std::cout << DIVISION << "ICMPЭ������ṹ" << DIVISION << std::endl;
    std::cout << "ICMP���ͣ�" << ih->type;
    switch (ih->type) {
    case 8:
        std::cout << "ICMP��������Э��" << std::endl;
        break;
    case 0:
        std::cout << "ICMP����Ӧ��Э��" << std::endl;
        break;
    default:
        break;
    }
    std::cout << "ICMP���룺" << ih->code << std::endl;
    std::cout << "��ʶ����" << ih->id << std::endl;
    std::cout << "�����룺" << ih->sequence << std::endl;
    std::cout << "ICMPУ��ͣ�" << ntohs(ih->checksum) << std::endl;
}

void add_to_map(std::map<std::string, int>& counter, ip_v4_address ip) {
    std::string ip_string;
    int amount = 0;
    std::map<std::string, int>::iterator iter;
    ip_string = std::to_string(ip.byte1) + "." + std::to_string(ip.byte2) + "." + std::to_string(ip.byte3) + "." + std::to_string(ip.byte4);
    iter = counter.find(ip_string);
    if (iter != counter.end()) {
        amount = iter->second;
    }
    counter.insert_or_assign(ip_string, ++amount);
}

void add_to_map(std::map<std::string, int>& counter, ip_v6_address ip) {
    std::string ip_string;
    int amount = 0;
    std::map<std::string, int>::iterator iter;
    ip_string = std::to_string(ip.part1) + ":" + std::to_string(ip.part2) + ":" + std::to_string(ip.part3) + ":" + std::to_string(ip.part4) + ":" + std::to_string(ip.part5) + ":" + std::to_string(ip.part6) + ":" + std::to_string(ip.part7) + ":" + std::to_string(ip.part8);
    iter = counter.find(ip_string);
    if (iter != counter.end()) {
        amount = iter->second;
    }
    counter.insert_or_assign(ip_string, ++amount);
}

void print_map(std::map<std::string, int> counter) {
    std::map<std::string, int>::iterator iter;
    std::cout << DIVISION << "����ͳ��" << DIVISION << std::endl;
    std::cout << "IP" << std::setfill(' ') << std::setw(45) << "����" << std::endl;
    for (iter = counter.begin(); iter != counter.end(); iter++) {
        std::cout << iter->first << std::setfill('.') << std::setw(45 - iter->first.length()) << iter->second << std::endl;
    }
}
