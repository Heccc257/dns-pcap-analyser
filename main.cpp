#include "src/dns_pcap_analyser.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

bool isFile(const std::string& path) {
    return fs::is_regular_file(fs::path(path));
}

bool isDirectory(const std::string& path) {
    return fs::is_directory(fs::path(path));
}

bool hasDatExtension(const std::string& filename) {
    return fs::path(filename).extension() == ".dat";
}

void collectDatFiles(const fs::path& dirPath, std::vector<fs::path>& datFiles) {
    for (const auto& entry : fs::directory_iterator(dirPath)) {
        const fs::path& path = entry.path();
        if (fs::is_directory(path)) {
            collectDatFiles(path, datFiles);
        } else if (fs::is_regular_file(path) && hasDatExtension(path.string())) {
            datFiles.push_back(path);
        }
    }
}

std::vector<fs::path> parseFiles(std::string path) {
	std::vector<fs::path> datFiles;
    if (isFile(path)) {
        if (hasDatExtension(path)) {
            std::cerr << "File with .dat extension: " << path << std::endl;
			datFiles.push_back(path);
        } else {
            std::cerr << "File exists but doesn't have .dat extension." << std::endl;
        }
    } else if (isDirectory(path)) {
        collectDatFiles(path, datFiles);
		if (datFiles.empty()) {
			std::cerr << "No .dat files found in the directory." << std::endl;
		} else {
			std::cerr << "Dat files in the directory:" << std::endl;
			for (const auto& datFile : datFiles) {
				std::cerr << datFile.string() << std::endl;
			}
		}
    } else {
        std::cout << "File or directory not found: " << path << std::endl;
    }
	return datFiles;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " [file/directory]" << std::endl;
        return 1;
    }

    std::string path = argv[1];
	auto files = parseFiles(path);

    return 0;
}
