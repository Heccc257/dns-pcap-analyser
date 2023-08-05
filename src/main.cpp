#include <iostream>
#include "dns_pcap_analyser/dns_pcap_analyser.h"
#include "command_line_parser.hpp"

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
    CommandLineParser parser(argc, argv);

    if (!parser.OptionExists("-f")) {
        std::cerr << "Error: -file option is required." << std::endl;
        parser.PrintUsageAndExit();
    }

    std::string inputFile = parser.GetOptionValue("-f");
    std::cout << "Input file: " << inputFile << std::endl;

    std::string outputDir;
    if (parser.OptionExists("-o")) {
        outputDir = parser.GetOptionValue("-o");
    } else {
        outputDir = parser.GetDefaultOutputDirectory();
    }
    std::cout << "Output directory: " << outputDir << std::endl;

    std::string path = inputFile;
    std::cerr << "path " << path << '\n';

	auto files = parseFiles(path);
	DNSPcapAnalyser analyser(files);
	result_t result;
	analyser.analyseAll(result);
    for (auto &entries: result) {
        std::set<std::string>s;
        std::cout << entries.first << '\n';
        for (auto &entry: entries.second) {
            s.insert(entry.IP);
        }
        for (auto &ip: s) {
            std::cout << ip << '\n';
        }
        puts("----------");
    }
    return 0;
}
