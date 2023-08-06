cmake_minimum_required(VERSION 3.10)
project(dns_pcap_analyser_project)

# Set the C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Directories
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(BIN_DIR "${CMAKE_SOURCE_DIR}/bin")
set(LIB_DIR "${CMAKE_SOURCE_DIR}/lib")

# Collect source files
file(GLOB_RECURSE SRC_FILES "${SRC_DIR}/*.cpp")
list(REMOVE_ITEM SRC_FILES "${SRC_DIR}/main.cpp")

# Create a static library
add_library(dns_pcap_analyser STATIC ${SRC_FILES})
target_include_directories(dns_pcap_analyser PUBLIC "${SRC_DIR}/dns_pcap_analyser")

# Create the executable
add_executable(dns_pcap_analyser_app "${SRC_DIR}/main.cpp")
target_link_libraries(dns_pcap_analyser_app PRIVATE dns_pcap_analyser)
set_target_properties(dns_pcap_analyser_app PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}")

# Set the library output directory
set_target_properties(dns_pcap_analyser PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${LIB_DIR}")
