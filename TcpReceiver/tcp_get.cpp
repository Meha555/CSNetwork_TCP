#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include "net-types.h"
#include "utils.hpp"

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("获取列表失败！\n");
        exit(1);
    }
    RecieveMenu(alldevs);
    return 0;
}