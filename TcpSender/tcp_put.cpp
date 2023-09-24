#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include <stdlib.h>
#include "net-types.h"
#include "utils.hpp"

#pragma execution_character_set("utf-8")

#define MSS 500  // 从控制台允许的最大输入长度
#define MTU_SIZE 65535    // 最大传输单元长度
#define TIME_OUT 1000     // 超时时间

void getIP(pcap_if_t* d, char* ip_addr, char* ip_netmask);              // 用ifget方法获取自身的IP和子网掩码
int getSelfMAC(pcap_t* adhandle, const char* ip_addr, u_char* ip_mac);  // 发送一个ARP请求来获取自身的MAC地址

DWORD WINAPI thread_send_arp(LPVOID lpParameter);
DWORD WINAPI thread_recv_arp(LPVOID lpParameter);

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取本地适配器列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        // 结果为-1代表出现获取适配器列表失败
        fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
        exit(1);
    }
    d = alldevs;
    SenderMenu(d);
    return 0;
}