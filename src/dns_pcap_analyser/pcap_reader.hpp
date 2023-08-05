#include <iostream>
#include <fstream>
#include <filesystem>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> // For close function
#include <netinet/in.h> // For ntohs

namespace fs = std::filesystem;

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

class PcapReader {
public:
    PcapReader(const fs::path& filepath) : filepath(filepath), mapped_file(nullptr), file_size(0), current_packet(nullptr) { }

    bool openFile() {
        // Open the file
        int fd = open(filepath.c_str(), O_RDONLY);
        if (fd == -1) {
            perror("open");
            return false;
        }

        // Get file size
        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat");
            close(fd);
            return false;
        }
        file_size = st.st_size;

        // Memory-map the file
        mapped_file = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);

        if (mapped_file == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return false;
        }

        close(fd);

        current_packet = static_cast<char*>(mapped_file) + sizeof(PcapGlobalHeader);
        return true;
    }

    const char* getNextPacketHdr() {
        if (mapped_file == nullptr || current_packet >= static_cast<char*>(mapped_file) + file_size) {
            return nullptr;
        }

        PcapPacketHeader* packet_header = reinterpret_cast<PcapPacketHeader*>(current_packet);
        // std::cerr << "reader size " << packet_header->incl_len << '\n';
        const char* packet_data = current_packet + sizeof(PcapPacketHeader);
        current_packet += sizeof(PcapPacketHeader) + packet_header->incl_len;

        // return packet_data;
        return reinterpret_cast<const char*>(packet_header);
    }

    void closeFile() {
        if (mapped_file != nullptr) {
            munmap(mapped_file, file_size);
            mapped_file = nullptr;
            file_size = 0;
            current_packet = nullptr;
        }
    }

    ~PcapReader() {
        closeFile();
    }

private:
    fs::path filepath;
    void* mapped_file;
    size_t file_size;
    char* current_packet;

};
