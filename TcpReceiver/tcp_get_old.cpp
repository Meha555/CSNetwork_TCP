//�����������ݰ���C++����
//���Ի�����ݰ����ȡ�ͨ����̫������ȷ���ϲ�Э�顢Դ��̫����ַ��Ŀ����̫����ַ��
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _XKEYCHECK_H 1
#endif

#include "pcap.h"
#include<winsock2.h>
#include <stdio.h>

//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data);
#define IPTOSBUFFERS 12
void ifprint(pcap_if_t* d);
char* iptos(u_long in);
int i = 0;
/*��������̫��Э���ʽ*/
struct ether_header
{
	uint8_t ether_dhost[6]; //Ŀ��Mac��ַ
	uint8_t ether_shost[6]; //ԴMac��ַ
	uint16_t ether_type;    //Э������
};

struct ip_header
{
	unsigned char Version_HLen;   //�汾��Ϣ4λ ��ͷ����4λ 1�ֽ�
	uint8_t    ip_tos;
	uint16_t   ip_length;
	uint16_t   ip_id;
	uint16_t   ip_off;
	uint8_t    ip_ttl;
	uint8_t    ip_protocol;
	uint16_t   ip_checksum;
	struct in_addr ip_souce_address;
	struct in_addr ip_destination_address;
};

//TCPͷ���ṹ�壬��20�ֽ�
struct TcpHeader
{
	unsigned short SrcPort;                        //Դ�˿ں�  2�ֽ�
	unsigned short DstPort;                        //Ŀ�Ķ˿ں� 2�ֽ�
	unsigned int SequenceNum;               //���  4�ֽ�
	unsigned int Acknowledgment;         //ȷ�Ϻ�  4�ֽ�
	unsigned char HdrLen;                         //�ײ�����4λ������λ6λ ��10λ
	unsigned char Flags;                          //��־λ6λ
	unsigned short AdvertisedWindow;  //���ڴ�С16λ 2�ֽ�
	unsigned short Checksum;                  //У���16λ   2�ֽ�
	unsigned short UrgPtr;						  //����ָ��16λ   2�ֽ�
};

void ip_protool_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	struct ip_header* ip_protocol;
	u_int header_length = 0;
	u_int offset;
	u_char tos;
	uint16_t checksum;
	u_int ip_len;                      //ip�ײ�����
	u_int ip_version;
	TcpHeader* tcp;                  //TCPͷ
	u_short sport, dport;
	//MAC�ײ���14λ�ģ�����14λ�õ�IPЭ���ײ�
	ip_protocol = (struct ip_header*)(packet_content + 14);

	ip_len = (ip_protocol->Version_HLen & 0xf) * 4;
	ip_version = ip_protocol->Version_HLen >> 4;
	tcp = (TcpHeader*)((u_char*)ip_protocol + ip_len);

	checksum = ntohs(ip_protocol->ip_checksum);
	tos = ip_protocol->ip_tos;
	offset = ntohs(ip_protocol->ip_off);
	/*��if�ж�ȥ�������ɽ�������TCP���ݰ� */
	if (*(unsigned long*)(packet_content + 30) == inet_addr("192.168.3.4")) {//������ն�ip��ַΪ192.168.3.4
		FILE* file_text_write = fopen("getLog.txt", "a");
		fprintf(file_text_write, "---------IPЭ��---------\n");
		fprintf(file_text_write, "�汾��:%d\n", ip_version);
		fprintf(file_text_write, "�ײ�����:%d\n", ip_len);
		fprintf(file_text_write, "��������:%d\n", tos);
		fprintf(file_text_write, "�ܳ���:%d\n", ntohs(ip_protocol->ip_length));
		fprintf(file_text_write, "��ʶ:%d\n", ntohs(ip_protocol->ip_id));
		fprintf(file_text_write, "ƫ��:%d\n", (offset & 0x1fff) * 8);
		fprintf(file_text_write, "����ʱ��:%d\n", ip_protocol->ip_ttl);
		fprintf(file_text_write, "Э������:%d\n", ip_protocol->ip_protocol);
		switch (ip_protocol->ip_protocol)
		{
		case 1: fprintf(file_text_write, "�ϲ�Э����ICMPЭ��\n"); break;
		case 2: fprintf(file_text_write, "�ϲ�Э����IGMPЭ��\n"); break;
		case 6: fprintf(file_text_write, "�ϲ�Э����TCPЭ��\n"); break;
		case 17: fprintf(file_text_write, "�ϲ�Э����UDPЭ��\n"); break;
		default:break;
		}
		fprintf(file_text_write, "�����:%d\n", checksum);
		fprintf(file_text_write, "ԴIP��ַ:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
		fprintf(file_text_write, "Ŀ�ĵ�ַ:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
		fprintf(file_text_write, "---------TCPЭ��---------\n");

		printf("---------IPЭ��---------\n");
		printf("�汾��:%d\n", ip_version);
		printf("�ײ�����:%d\n", ip_len);
		printf("��������:%d\n", tos);
		printf("�ܳ���:%d\n", ntohs(ip_protocol->ip_length));
		printf("��ʶ:%d\n", ntohs(ip_protocol->ip_id));
		printf("ƫ��:%d\n", (offset & 0x1fff) * 8);
		printf("����ʱ��:%d\n", ip_protocol->ip_ttl);
		printf("Э������:%d\n", ip_protocol->ip_protocol);
		switch (ip_protocol->ip_protocol)
		{
		case 1: printf("�ϲ�Э����ICMPЭ��\n"); break;
		case 2: printf("�ϲ�Э����IGMPЭ��\n"); break;
		case 6: printf("�ϲ�Э����TCPЭ��\n"); break;
		case 17: printf("�ϲ�Э����UDPЭ��\n"); break;
		default:break;
		}

		printf("�����:%d\n", checksum);
		printf("ԴIP��ַ:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
		printf("Ŀ�ĵ�ַ:%s\n", inet_ntoa(ip_protocol->ip_destination_address));

		//�������ֽ�����ת���������ֽ�����
		printf("---------TCPЭ��---------\n");
		sport = ntohs(tcp->SrcPort);
		dport = ntohs(tcp->DstPort);
		printf("Դ�˿�:%d Ŀ�Ķ˿�:%d\n", sport, dport);
		printf("���:%d\n", ntohl(tcp->SequenceNum));
		printf("ȷ�Ϻ�:%d\n", ntohl(tcp->Acknowledgment));
		printf("ƫ�Ƶ�ַ���ײ����ȣ�:%d\n", (tcp->HdrLen >> 4) * 4);
		printf("��־λ:%d\n", tcp->Flags);
		printf("����UGR:%d\n", (tcp->Flags & 0x20) / 32);
		printf("ȷ��ACK:%d\n", (tcp->Flags & 0x10) / 16);
		printf("����PSH:%d\n", (tcp->Flags & 0x08) / 8);
		printf("��λRST:%d\n", (tcp->Flags & 0x04) / 4);
		printf("ͬ��SYN:%d\n", (tcp->Flags & 0x02) / 2);
		printf("��ֹFIN:%d\n", tcp->Flags & 0x01);
		printf("���ڴ�С:%d\n", ntohs(tcp->AdvertisedWindow));
		printf("У���:%d\n", ntohs(tcp->Checksum));
		printf("����ָ��:%d\n", ntohs(tcp->UrgPtr));

		fprintf(file_text_write, "Դ�˿�:%d Ŀ�Ķ˿�:%d\n", sport, dport);
		fprintf(file_text_write, "���:%d\n", ntohl(tcp->SequenceNum));
		fprintf(file_text_write, "ȷ�Ϻ�:%d\n", ntohl(tcp->Acknowledgment));
		fprintf(file_text_write, "ƫ�Ƶ�ַ���ײ����ȣ�:%d\n", (tcp->HdrLen >> 4) * 4);
		fprintf(file_text_write, "��־λ:%d\n", tcp->Flags);
		fprintf(file_text_write, "����UGR:%d\n", (tcp->Flags & 0x20) / 32);
		fprintf(file_text_write, "ȷ��ACK:%d\n", (tcp->Flags & 0x10) / 16);
		fprintf(file_text_write, "����PSH:%d\n", (tcp->Flags & 0x08) / 8);
		fprintf(file_text_write, "��λRST:%d\n", (tcp->Flags & 0x04) / 4);
		fprintf(file_text_write, "ͬ��SYN:%d\n", (tcp->Flags & 0x02) / 2);
		fprintf(file_text_write, "��ֹFIN:%d\n", tcp->Flags & 0x01);
		fprintf(file_text_write, "���ڴ�С:%d\n", ntohs(tcp->AdvertisedWindow));
		fprintf(file_text_write, "У���:%d\n", ntohs(tcp->Checksum));
		fprintf(file_text_write, "����ָ��:%d\n", ntohs(tcp->UrgPtr));

		char* data;
		data = (char*)((u_char*)tcp + 20);
		printf("---------���ݲ���---------\n");
		printf("���ݲ���:%s\n", data);

		fprintf(file_text_write, "---------���ݲ���---------\n");
		fprintf(file_text_write, "���ݲ���:%s\n", data);
		fclose(file_text_write);
	}
}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;
	struct ether_header* ethernet_protocol;
	u_char* mac_string;
	static int packet_number = 1;

	ethernet_protocol = (struct ether_header*)packet_content;//������ݰ�����
	ethernet_type = ntohs(ethernet_protocol->ether_type);//�����̫������
	if (ethernet_type == 0x0800)//��������IPЭ��
	{
		ip_protool_packet_callback(argument, packet_header, packet_content);
	}

	packet_number++;

}

int main()
// {
//      pcap_t* pcap_handle; //winpcap���
//      char error_content[PCAP_ERRBUF_SIZE]; //�洢������Ϣ
//      bpf_u_int32 net_mask; //�����ַ
//      bpf_u_int32 net_ip;  //�����ַ
//      char *net_interface;  //����ӿ�
//      struct bpf_program bpf_filter;  //BPF���˹���
//      char bpf_filter_string[]="ip"; //���˹����ַ�����ֻ����IPv4�����ݰ�
//      net_interface=pcap_lookupdev(error_content); //�������ӿ�
//      pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content); //��������ַ�������ַ
//      pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content); //������ӿ�
//      pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,net_ip); //������˹���
//      pcap_setfilter(pcap_handle,&bpf_filter);//���ù��˹���
//      if (pcap_datalink(pcap_handle)!=DLT_EN10MB) //DLT_EN10MB��ʾ��̫��
//          return 0;
//      pcap_loop(pcap_handle,10,ethernet_protocol_packet_callback,NULL); //����10�����ݰ����з���
//      pcap_close(pcap_handle);
//      return 0;
// }
{
	FILE* file_text_write = fopen("getLog.txt", "w");
	fclose(file_text_write);
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/*ȡ���б�*/
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		exit(1);
	}
	/*����б�*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		ifprint(d);
	}
	if (i == 0)
	{

		printf("\nNo interfaces found!Make sure WinPcap is installed.\n");
		char c = getchar();
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum <1 || inum >i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		char c = getchar();
		return -1;
	}

	//ת��ѡ����豸
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	//��ʧ��
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter.%s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		char c = getchar();
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);
	//�ͷ��б�
	pcap_freealldevs(alldevs);
	//��ʼ��׽
	//pcap_loop(adhandle,0,ip_protool_packet_callback,NULL);
	pcap_loop(adhandle, 0, ethernet_protocol_packet_callback, NULL);
	char c = getchar();
	return 0;
}
void ifprint(pcap_if_t* d)
{
	pcap_addr_t* a;
	printf("%d.%s", ++i, d->name);
	if (d->description)
	{
		printf("\tDescription:(%s)\n", d->description);
	}
	else {
		printf("\t(No description available)\n");
	}
	printf("\tLoopback:%s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	for (a = d->addresses; a != NULL; a = a->next)
	{
		printf("\tAddress Family:#%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name:AF_INET\n");
			if (a->addr)
			{
				printf("\tAddress:%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
			}
			if (a->netmask)
			{
				printf("\tNetmask:%s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
			}
			if (a->broadaddr)
			{
				printf("\tBroadcast Address:%s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
			}
			if (a->dstaddr)
			{
				printf("\tDestination Address:%s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
			}
			break;
		default:
			printf("\tAddressFamilyName:Unknown\n");
			break;
		}
	}
}
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pcap_data)
//{
//	struct tm* ltime;
//	char timestr[16];
//	ltime = localtime(&header->ts.tv_sec);
//	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
//	printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//}
