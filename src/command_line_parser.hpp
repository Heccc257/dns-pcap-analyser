#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

class CommandLineParser {
public:
    CommandLineParser(int argc, char* argv[]) : argc(argc), argv(argv) {}

    std::string GetOptionValue(const std::string& option) const {
        auto it = std::find(argv, argv + argc, option);
        if (it != argv + argc && ++it != argv + argc) {
            return *it;
        }
        return "";
    }

    bool OptionExists(const std::string& option) const {
        return std::find(argv, argv + argc, option) != argv + argc;
    }

    std::string GetDefaultOutputDirectory() const {
        return "test/output.txt";
    }

    void PrintUsageAndExit() const {
        std::cerr << "Usage: " << argv[0] << " -file [file] -output [output_dir]" << std::endl;
        exit(1);
    }

private:
    int argc;
    char** argv;
};
