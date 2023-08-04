# Makefile for creating a static library libA.a

# Compiler and flags
CC := g++
CFLAGS := -Wall -Wextra -pedantic -std=c++11
LDFLAGS := -lpcap

# Directories
SRC_DIR := src
BUILD_DIR := build
LIB_DIR := lib

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.cpp)

# Object files
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))

# Library name
LIB_NAME := libdns_pcap_analyser.a

# Targets
all: $(LIB_DIR)/$(LIB_NAME)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/$(LIB_NAME): $(OBJS)
	@mkdir -p $(LIB_DIR)
	ar rcs $@ $(OBJS)

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)/$(LIB_NAME)

.PHONY: all clean
