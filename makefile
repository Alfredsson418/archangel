# Set compiler
CC = g++

# Set name for the executable
NAME = archangel

# Directories
CORE = core
LIB = $(CORE)/lib
BUILD = build
SRC = $(CORE)/src
VERSION_HEADER = $(BUILD)/generated/archangel_version.hpp
GIT_COMMIT = $(shell git rev-parse --verify HEAD 2>/dev/null)
ifeq ($(strip $(GIT_COMMIT)),)
$(error Unable to determine the Git commit hash required for the backend version)
endif

# ------------------------------------------------------
# 					Code compilation
# ------------------------------------------------------

# Flags for compiling
DEBUG_CFLAGS = -std=c++20 -Wall -g
RELEASE_CFLAGS = -std=c++20
TEST_CFLAGS = -std=c++20 -Wall -O0 -g0
LDFLAGS = -lnftables -lsqlite3 -largon2 -lcrypto -lrt -ldl -pthread
# lm is used by argtable3


# Get all the source files in the SRC directory and its subdirectories
SRCFILES = $(shell find $(SRC) -name '*.cpp')
LIB_SRCFILES = $(shell find $(LIB) -name '*.cpp')


# Generate object file names from source file names
DEBUG_OBJFILES = $(patsubst $(SRC)/%.cpp, $(BUILD)/debug/$(SRC)/%.o, $(SRCFILES))
DEBUG_LIB_OBJFILES = $(patsubst $(LIB)/%.cpp, $(BUILD)/debug/$(LIB)/%.o, $(LIB_SRCFILES))
RELEASE_OBJFILES = $(patsubst $(SRC)/%.cpp, $(BUILD)/release/$(SRC)/%.o, $(SRCFILES))
RELEASE_LIB_OBJFILES = $(patsubst $(LIB)/%.cpp, $(BUILD)/release/$(LIB)/%.o, $(LIB_SRCFILES))
TEST_SRCFILES = $(shell find $(CORE)/tests -name '*.cpp')
TEST_BINARY = $(BUILD)/$(CORE)/tests/backend_tests

.PHONY: debug release test clean FORCE

FORCE:

$(VERSION_HEADER): FORCE
	@mkdir -p $(@D)
	@printf '#pragma once\n#define ARCHANGEL_GIT_COMMIT "%s"\n' "$(GIT_COMMIT)" > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

$(BUILD)/debug/$(SRC)/http/server.o $(BUILD)/release/$(SRC)/http/server.o: $(VERSION_HEADER)

# Target to build the executable with debug flags
debug: $(DEBUG_OBJFILES) $(DEBUG_LIB_OBJFILES)
	@echo "Building $(NAME) in debug mode"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD $^ -o $(NAME) $(LDFLAGS)
	@echo "Done!"


# Target to build the executable with release flags
build_release: $(RELEASE_OBJFILES) $(RELEASE_LIB_OBJFILES)
	@echo "Building $(NAME) in release mode"
	@$(CC) $(RELEASE_CFLAGS) $^ -o $(NAME) $(LDFLAGS)
	@echo "Done!"

$(TEST_BINARY): $(TEST_SRCFILES) $(SRC)/auth/auth_crypto.cpp $(SRC)/auth/providers/sqlite_auth_provider.cpp $(SRC)/auth/sqlite_auth_storage.cpp $(SRC)/auth/secret_input.cpp $(SRC)/logger.cpp $(SRC)/logs/log_sources.cpp $(SRC)/cli/firewall_config.cpp $(SRC)/network/address.cpp $(SRC)/firewall/config.cpp $(SRC)/config/runtime_config.cpp $(SRC)/http/authentication.cpp $(SRC)/http/api/auth.cpp $(SRC)/http/api/logs.cpp $(SRC)/firewall/providers/nft_import.cpp $(SRC)/firewall/providers/nft_statistics.cpp $(SRC)/http/api/rules.cpp $(SRC)/http/api/stats.cpp
	@mkdir -p $(@D)
	@echo "Building backend tests"
	@$(CC) $(TEST_CFLAGS) -I$(CORE)/include -I$(LIB) $^ -o $@ -lsqlite3 -largon2 -lcrypto -lrt -ldl -pthread

test: $(TEST_BINARY)
	@$(TEST_BINARY)


# Rules to compile debug and release objects independently, so build tags
# cannot be inherited when switching build modes.
$(BUILD)/debug/$(SRC)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD -I$(BUILD)/generated -c -o $@ $<

$(BUILD)/debug/$(LIB)/%.o: $(LIB)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD -I$(BUILD)/generated -c -o $@ $<

$(BUILD)/release/$(SRC)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(RELEASE_CFLAGS) -I$(BUILD)/generated -c -o $@ $<

$(BUILD)/release/$(LIB)/%.o: $(LIB)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(RELEASE_CFLAGS) -I$(BUILD)/generated -c -o $@ $<


# Target to clean up generated file
clean:
	@rm -rf $(BUILD) $(NAME)
