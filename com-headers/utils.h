﻿#pragma once
#include <time.h>

#define MEMCPY(dest,src,type) memcpy(dest,src,sizeof(type));
#define MEMSET(dest,data,type) memset(dest,data,sizeof(type));
#define ALLOCATE(type,num) (type*)malloc(sizeof(type)*num);

#define ETH_ARP 0x0806                                                         // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE 1                                                          // 硬件类型字段值为表示以太网地址
#define ETH_IP 0x0800                                                          // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST 1                                                          // ARP请求
#define ARP_REPLY 2                                                            // ARP应答
#define IPTOSBUFFERS 12

//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data) {
//	struct tm* ltime;
//	char timestr[16];
//	time_t temp = header->ts.tv_sec;
//	ltime = localtime(&temp);
//	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
//	printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//}

/* 将数字类型的IPv4地址转换成字符串类型的 */
char* iptos(u_long in) {
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/* 将数字类型的IPv6地址转换成字符串类型的 */
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen){
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
		NI_NUMERICHOST) != 0) address = NULL;
	return address;
}

// 获得校验和的方法
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

void ifprint(pcap_if_t* dev, int &i) {
	printf("-----------------------------------------------------------------\n序号: %d\n名称: %s\n", ++i, dev->name);
	if (dev->description) {
		// 打印适配器的描述信息
		printf("适配器描述:%s\n", dev->description);
	}
	else {
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
				printf("\IPv6地址: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			}
			break;
		default:
			printf("\t未知的IP地址类型\n");
			break;
		}
	}
}
