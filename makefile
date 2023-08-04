# Makefile for creating a static library libdns_pcap_analyser.a and an executable

# Compiler and flags
CC := g++
CFLAGS := -Wall -Wextra -pedantic -std=c++11
LDFLAGS := -lpcap

# Directories
SRC_DIR := src
BUILD_DIR := build
LIB_DIR := lib
BIN_DIR := bin

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.cpp)
MAIN_SRCS := main.cpp

# Object files
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))

# Library name
LIB_NAME := libdns_pcap_analyser.a

# Executable name
EXEC_NAME := dns_pcap_analyser

# Targets
all: $(LIB_DIR)/$(LIB_NAME) $(BIN_DIR)/$(EXEC_NAME)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/$(LIB_NAME): $(OBJS)
	@mkdir -p $(LIB_DIR)
	ar rcs $@ $(OBJS)

$(BIN_DIR)/$(EXEC_NAME): $(MAIN_SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -L$(LIB_DIR) -ldns_pcap_analyser $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)/$(LIB_NAME) $(BIN_DIR)/$(EXEC_NAME)

.PHONY: all clean
