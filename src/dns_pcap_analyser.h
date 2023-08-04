#ifndef DNS_PCAP_ANALYSER_H
#define DNS_PCAP_ANALYSER_H

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>
#include <iostream>

// DNS头部结构
struct DNSHeader {
	u_short id;
	u_short flags;
	u_short questions;
	u_short answers;
	u_short authority;
	u_short additional;
};

// DNS查询结构
struct DNSQuery {
	u_short type;
	u_short _class;
};

// DNS回答结构
struct DNSAnswer {
	u_short name;
	u_short type;
	u_short _class;
	u_short ttl1;
	u_short ttl2;
	u_short dataLength;
};

class DNSPcapAnalyser {
public:
	void processPacket(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packetData);

private:
  	pcap_t *pcapHandle;
	char errbuf[PCAP_ERRBUF_SIZE];
};
#endif