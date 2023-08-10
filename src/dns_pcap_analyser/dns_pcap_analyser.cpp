#include "dns_pcap_analyser.h"

int cnt;
void DNSPcapAnalyser::processPacket(u_char *userData, const struct PcapPacketHeader *pkthdr, const u_char *packetData) {

    DNSPcapAnalyser* analyserThis = reinterpret_cast<DNSPcapAnalyser*>(userData);
    result_t& result = *analyserThis->mResult;
    cnt ++ ;
    // std::cerr << "cnt = " << cnt << '\n';
    if (pkthdr->incl_len == 0) {
        std::cerr << "capture end\n";
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

    
    // 计算 UDP 数据包的偏移量
    int ipHeaderSize = 20; // IP 头部的长度为20字节

    // 解析 UDP 头部
    // const struct udphdr *udpHeader = (struct udphdr *)(packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize);

    // 计算 DNS 数据包的偏移量
    int udpHeaderSize = 8; // UDP 头部的长度为8字节

    // 解析 DNS 头部
    const struct DNSHeader *dnsHeader = (struct DNSHeader *)(packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + udpHeaderSize);

    if ((dnsHeader->flags>>1) & 1) { // 判断truncate标志位
        // 学校100多字节就会truncated,所以先忽略
        // std::cerr << "message is truncated " << std::dec << cnt << '\n';
        // return ;
    }
    
    // 获取查询问题部分的起始位置
    const u_char *queryStart = (packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + udpHeaderSize + sizeof(struct DNSHeader));

    // 如果不是 response 报文则 return
    if (ipHeader->ip_p != IPPROTO_UDP || ntohs(udpHeader->uh_sport) != 53) return;

    if (ntohs(dnsHeader->questions) > 1) {
        // 先不考虑query数量大于1的情况
        std::cerr << "Packet num " << cnt << " more than 1 queries\n";
        return ;
    }

    // 遍历查询问题
    const u_char *currentByte = queryStart;
    const u_char *endByte = packetData + pkthdr->incl_len;

    auto truncate = [&]() { std::cerr << "truncated packet number: " << std::dec << cnt << '\n'; };


    std::string domain;
    bool is_pointer = 0;
    int temcnt = 0;
    int readLimit;
    auto read_point_format = [&]() {
        readLimit = 255;
        if (currentByte >= endByte) {
            truncate(); // 
            return 0;
        }
        domain = "";
        is_pointer = 0;
        const u_char* lst;
        while (*currentByte != 0) {
            if (cnt == 64726)
                std::cerr << (void*)currentByte << " begin = " << (void*)packetData << '\n';
            if (--readLimit == 0) {
                std::cerr << "超过 read limit  packet " << cnt << '\n';
            }
            if ((*currentByte & 0xC0) == 0xC0) {
                if (!is_pointer) {
                    is_pointer = 1;
                    lst = currentByte;
                }
                // 判断是否为指针
                int pointer = (*currentByte & 0x3F) << 8 | *(currentByte + 1);
                // currentByte = packetData + virtualLanSize + ethernetHeaderSize + ipHeaderSize + pointer;
                currentByte = reinterpret_cast<const u_char*>(dnsHeader) + pointer;

                // 如果字符串是以指针的形式保存，则currentByte的最终位置为当前位置向后位移两个字节。
            } else {
                int labelLength = *currentByte;
                if (labelLength > 63) {
                    std::cerr << "label 长度过大 packet " << cnt << '\n';
                    domain = "";
                    return 1;
                }

                currentByte++;
                for (int j = 0; j < labelLength; ++j) {
                    domain += *currentByte;
                    currentByte++;
                }
                domain += '.';
            }

            if (currentByte >= endByte) {
                truncate(); // 
                return 0;
            }
        }
        if (domain.size() && *(--domain.end()) == '.')
            domain.pop_back(); // 移除最后的 '.'

        if (is_pointer){
            currentByte = lst + 2;
        }
        
        return 1;
    };

    bool isSOA = 0;

    const struct DNSQuery *queryHeader;
    for (int i = 0; i < ntohs(dnsHeader->questions); ++i) {
        // 解析域名
        if (!read_point_format()) return ;

        // 每个报文最后有四个字节的Query头
        queryHeader = reinterpret_cast<const DNSQuery*>(currentByte + 1);

        // currentByte目前处于字符串末尾的0x00，所以要偏移5个字节
        currentByte += 5;

        if (currentByte > endByte) {
            truncate();
            return ;
        }
        if (queryHeader->type == 0x600) {
            isSOA = 1;
        }
    }
    // SOA报文的response部分的name只有一个字节
    if (isSOA) {
        // std::cerr << "SOA packet " << cnt << '\n';
        return ;
    }


    // 解析回答部分
    const u_char *answerStart;
    dns_entries &entries = result[domain];
    for (int j = 0; j < htons(dnsHeader->answers); ++j) {
        // TODO 6680号和64726号报文的格式不统一

        if (!read_point_format()) return ;

        if (!is_pointer) { // 如果最后不是以指针形式结尾
            if (*reinterpret_cast<const ushort*>(currentByte) == 0)
                currentByte -= 1 ;
            else currentByte -= 2;
            // if ((reinterpret_cast<const unsigned long long>(currentByte) - reinterpret_cast<const unsigned long long>(packetData))&0x1) // 字节对齐
            //     currentByte ++;
        } else currentByte -= 2;

        // 如果是点分字符串形式，则answerStart起始位置为字符串末尾的0x00
        answerStart = currentByte;

        const struct DNSAnswer *answerHeader = (struct DNSAnswer *)(answerStart);
        const u_char *answerData = answerStart + sizeof(struct DNSAnswer);

        if (answerData + ntohs(answerHeader->dataLength) > endByte) {
            truncate();
            return ;
        }

        if (ntohs(answerHeader->type) == ntohs(queryHeader->type) && ntohs(answerHeader->_class) == ntohs(queryHeader->_class)) {            // 处理回答部分类型为 A 类型（IPv4地址）的记录
            if (ntohs(answerHeader->type) == 1 && answerHeader->dataLength == htons(4)) {
                struct in_addr answerIPv4;
                memcpy(&answerIPv4, answerData, sizeof(struct in_addr));
                // 打印域名和对应的 IP 地址

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
        currentByte = answerStart;
    }
    return ;
}

void DNSPcapAnalyser::open(std::vector<fs::path>& _files) {
    for (auto &f: _files)
        files.push_back(f);
}

bool DNSPcapAnalyser::analyse(const fs::path& filePath, result_t &result) {
    cnt = 0;
    this->mResult = &result;
    std::cerr << "begin analyse " << filePath.string() << '\n';
    PcapReader reader(filePath);
    if (!reader.openFile()) {
        std::cerr << "Error opening pcap file: \n";
        return 0;
    }
    
    const char* hdr;
    while ((hdr = reader.getNextPacketHdr()) != nullptr) {
        const char* packet_data = hdr + sizeof(PcapPacketHeader);
        DNSPcapAnalyser::processPacket(reinterpret_cast<u_char*>(this), 
            reinterpret_cast<const PcapPacketHeader *>(hdr), reinterpret_cast<const u_char *>(packet_data));
    }
    return 1;
}
bool DNSPcapAnalyser::analyseAll(result_t &result) {
    for (auto &filePath: files) {
        if (!analyse(filePath, result))
            return 0;
    }

    return 1;
}

