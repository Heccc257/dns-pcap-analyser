#ifndef DNS_PCAP_ANALYSER_H
#define DNS_PCAP_ANALYSER_H

// #include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <map>
#include <set>

#include "pcap_reader.hpp"

namespace fs = std::filesystem;

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
	// u_short name;
	u_short type;
	u_short _class;
	u_short ttl1;
	u_short ttl2;
	u_short dataLength;
};

// 设置成entry, 方便以后支持更多的分析内容

typedef struct {
	enum class IPVersion {
		IPv4,
		IPv6,
	};
	IPVersion ip_version;
	std::string IP;
} dns_entry;

typedef std::vector<dns_entry> dns_entries;

typedef std::map<std::string, dns_entries> result_t ;

class DNSPcapAnalyser {
public:
	// static void processPacket(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packetData);
	static void processPacket(u_char *userData, const struct PcapPacketHeader *pkthdr, const u_char *packetData);
	DNSPcapAnalyser() = default;
	DNSPcapAnalyser(std::vector<fs::path>& _files): files(_files) { };
	~DNSPcapAnalyser() = default;
	void open(std::vector<fs::path>& _files);
	bool analyse(const fs::path& path, result_t &results);
	bool analyseAll(result_t &result);
private:
	std::vector<fs::path> files;
	result_t* mResult;
};


#endif