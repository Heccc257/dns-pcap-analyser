#include "dns_pcap_analyser.h"

int cnt;
void DNSPcapAnalyser::processPacket(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packetData) {
    DNSPcapAnalyser* analyserThis = reinterpret_cast<DNSPcapAnalyser*>(userData);
    result_t& result = *analyserThis->mResult;
    // std::cerr << pkthdr->caplen << '\n';
    // 已经捕获了所有报文
    {
        cnt ++ ;
        if (cnt % 1000 == 0) {
            std::cerr << "cnt = " << cnt << '\n';
        }
    }
    if (pkthdr->caplen == 0) {
        std::cerr << "capture end\n";
        pcap_breakloop(analyserThis->pcapHandle);
        return ;
    }
    // return ;
    // 解析以太网头部
    // const struct ether_header *ethernetHeader = (struct ether_header *)packetData;

    // 计算 IP 数据包的偏移量
    int ethernetHeaderSize = 14; // 以太网头部的长度为14字节
    int virtualLanSize = 4;

    // 解析 IP 头部
    const struct ip *ipHeader = (struct ip *)(packetData + virtualLanSize + sizeof(struct ether_header));
    struct udphdr *udpHeader = (struct udphdr *)(packetData + virtualLanSize + sizeof(struct ether_header) + sizeof(struct ip));

    // 如果不是 response 报文则 return
    if (ipHeader->ip_p != IPPROTO_UDP || ntohs(udpHeader->uh_sport) != 53) return;
    
    // 计算 UDP 数据包的偏移量
    int ipHeaderSize = 20; // IP 头部的长度为20字节

    // 解析 UDP 头部
    // const struct udphdr *udpHeader = (struct udphdr *)(packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize);

    // 计算 DNS 数据包的偏移量
    int udpHeaderSize = 8; // UDP 头部的长度为8字节

    // 解析 DNS 头部
    const struct DNSHeader *dnsHeader = (struct DNSHeader *)(packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + udpHeaderSize);

    // 获取查询问题部分的起始位置
    const u_char *queryStart = (packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + udpHeaderSize + sizeof(struct DNSHeader));

    if (ntohs(dnsHeader->questions) > 1) {
        // 先不考虑query数量大于1的情况
        return ;
    }

    // 遍历查询问题
    const u_char *currentByte = queryStart;
    std::string domain;
    for (int i = 0; i < ntohs(dnsHeader->questions); ++i) {
        // 解析域名

        while (*currentByte != 0) {
            if ((*currentByte & 0xC0) == 0xC0) { 
                // 判断是否为指针
                int pointer = (*currentByte & 0x3F) << 8 | *(currentByte + 1);
                currentByte = packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + pointer;
            } else {
                int labelLength = *currentByte;
                currentByte++;
                for (int j = 0; j < labelLength; ++j) {
                    domain += *currentByte;
                    currentByte++;
                }
                domain += '.';
            }
        }
        if (domain.size() && *(--domain.end()) == '.')
            domain.pop_back(); // 移除最后的 '.'
    }
    // std::cerr << "cnt = " << cnt << '\n';
    // 解析回答部分
    const u_char *answerStart = currentByte + 5; // 跳过查询问题的类型和类别

    // 这里需要获取一下query的类型和类别
    const struct DNSQuery *queryHeader = (struct DNSQuery *)(currentByte + 1);

    // std::cerr << "domain: " << domain << '\n';
    dns_entries &entries = result[domain];
    for (int j = 0; j < htons(dnsHeader->answers); ++j) {
        const struct DNSAnswer *answerHeader = (struct DNSAnswer *)(answerStart);
        const u_char *answerData = answerStart + sizeof(struct DNSAnswer);


        if (ntohs(answerHeader->type) == ntohs(queryHeader->type) && ntohs(answerHeader->_class) == ntohs(queryHeader->_class)) {
            // 处理回答部分类型为 A 类型（IPv4地址）的记录
            if (ntohs(answerHeader->type) == 1 && answerHeader->dataLength == htons(4)) {
                struct in_addr answerIPv4;
                memcpy(&answerIPv4, answerData, sizeof(struct in_addr));
                // 打印域名和对应的 IP 地址
                // std::cout << "Domain: " << domain << ", IP Address: " << inet_ntoa(answerIPv4) << std::endl;
                
                dns_entry tem;
                tem.ip_version = dns_entry::IPVersion::IPv4;
                tem.IP = std::string(inet_ntoa(answerIPv4));
                entries.push_back(tem);
            }
            // 处理回答部分类型为 AAAA 类型（IPv6地址）的记录
            if (ntohs(answerHeader->type) == 28 && answerHeader->dataLength == htons(16)) {
                struct in6_addr answerIPv6;
                memcpy(&answerIPv6, answerData, sizeof(struct in6_addr));
                char ipv6Buffer[INET6_ADDRSTRLEN];

                // 打印域名和对应的 IP 地址
                // std::cout << "Domain: " << domain << ", IP Address: " << inet_ntop(AF_INET6, &answerIPv6, ipv6Buffer, sizeof(ipv6Buffer)) << std::endl;

                dns_entry tem;
                tem.ip_version = dns_entry::IPVersion::IPv6;
                tem.IP = std::string(inet_ntop(AF_INET6, &answerIPv6, ipv6Buffer, sizeof(ipv6Buffer)));
                entries.push_back(tem);
            }
        }

        // 移动到下一个回答部分
        answerStart += sizeof(struct DNSAnswer) + ntohs(answerHeader->dataLength);
    }
}

void DNSPcapAnalyser::open(std::vector<fs::path>& _files) {
    for (auto &f: _files)
        files.push_back(f);
}

bool DNSPcapAnalyser::analyse(const fs::path& filePath, result_t &result) {
    this->mResult = &result;
    std::cerr << "begin analyse " << filePath.string() << '\n';
    pcapHandle = pcap_open_offline(filePath.string().c_str(), errbuf);
    if (pcapHandle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 0;
    }
    // 循环读取 pcap 文件中的数据包

    pcap_loop(pcapHandle, 0, DNSPcapAnalyser::processPacket, reinterpret_cast<u_char*>(this));

    // // 关闭 pcap 文件
    pcap_close(pcapHandle);

    return 1;
}
bool DNSPcapAnalyser::analyseAll(result_t &result) {
    for (auto &filePath: files) {
        if (!analyse(filePath, result))
            return 0;
    }

    return 1;
}
