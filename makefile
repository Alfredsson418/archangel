# Set compiler
CC = g++

# Set name for the executable
NAME = archangel

# Directories
# The binary is built into OUT. Debug builds keep their private state, including
# app.log, in OUT/.archangel-dev beside it.
OUT = bin
TARGET = $(OUT)/$(NAME)
CORE = core
LIB = $(CORE)/lib
BUILD = build
SRC = $(CORE)/src
VERSION_HEADER = $(BUILD)/generated/archangel_version.hpp
# Includes are written relative to these roots, for example
# "http/server.hpp" or "json/json.hpp".
INCLUDE_FLAGS = -I$(CORE)/include -I$(LIB) -I$(BUILD)/generated
# Enables cpp-httplib's TLS server; it must be defined for every file that
# includes cpp-httplib so they all see the same class layouts.
INCLUDE_FLAGS += -DCPPHTTPLIB_OPENSSL_SUPPORT
GIT_COMMIT = $(shell git rev-parse --verify HEAD 2>/dev/null)
ifeq ($(strip $(GIT_COMMIT)),)
$(error Unable to determine the Git commit hash required for the backend version)
endif

# ------------------------------------------------------
# 					Code compilation
# ------------------------------------------------------

# Flags for compiling
DEBUG_CFLAGS = -std=c++20 -Wall -Wextra -g
# The backend runs privileged and listens on the network, so release builds
# enable optimization-dependent fortification, stack protection, and full RELRO.
RELEASE_CFLAGS = -std=c++20 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
RELEASE_LDFLAGS = -pie -Wl,-z,relro,-z,now
TEST_CFLAGS = -std=c++20 -Wall -O0 -g0
LDFLAGS = -lnftables -lsqlite3 -largon2 -lssl -lcrypto -lrt -ldl -pthread
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
# The test binary links every backend source except the entry point and
# composition root, the HTTP server (which needs the generated version header),
# and the nftables provider (which needs libnftables and a live ruleset).
TEST_EXCLUDED_SRCFILES = $(SRC)/main.cpp $(SRC)/app/application.cpp \
	$(SRC)/http/server.cpp $(SRC)/firewall/providers/nft.cpp \
	$(SRC)/firewall/providers/nft_config.cpp
TEST_APP_SRCFILES = $(filter-out $(TEST_EXCLUDED_SRCFILES),$(SRCFILES))
TEST_BINARY = $(BUILD)/$(CORE)/tests/backend_tests

.PHONY: debug build_release test clean clean-dev-state run bootstrap-admin config FORCE

FORCE:

$(VERSION_HEADER): FORCE
	@mkdir -p $(@D)
	@printf '#pragma once\n#define ARCHANGEL_GIT_COMMIT "%s"\n' "$(GIT_COMMIT)" > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

$(BUILD)/debug/$(SRC)/http/server.o $(BUILD)/release/$(SRC)/http/server.o: $(VERSION_HEADER)

# Target to build the executable with debug flags
debug: $(DEBUG_OBJFILES) $(DEBUG_LIB_OBJFILES)
	@mkdir -p $(OUT)
	@echo "Building $(TARGET) in debug mode"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD $^ -o $(TARGET) $(LDFLAGS)
	@echo "Done!"


# Target to build the executable with release flags
build_release: $(RELEASE_OBJFILES) $(RELEASE_LIB_OBJFILES)
	@mkdir -p $(OUT)
	@echo "Building $(TARGET) in release mode"
	@$(CC) $(RELEASE_CFLAGS) $(RELEASE_LDFLAGS) $^ -o $(TARGET) $(LDFLAGS)
	@echo "Done!"

$(TEST_BINARY): $(TEST_SRCFILES) $(TEST_APP_SRCFILES)
	@mkdir -p $(@D)
	@echo "Building backend tests"
	@$(CC) $(TEST_CFLAGS) $(INCLUDE_FLAGS) $^ -o $@ -lsqlite3 -largon2 -lssl -lcrypto -lrt -ldl -pthread

test: $(TEST_BINARY)
	@$(TEST_BINARY)


# Rules to compile debug and release objects independently, so build tags
# cannot be inherited when switching build modes.
$(BUILD)/debug/$(SRC)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD $(INCLUDE_FLAGS) -c -o $@ $<

$(BUILD)/debug/$(LIB)/%.o: $(LIB)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(DEBUG_CFLAGS) -DARCHANGEL_DEV_BUILD $(INCLUDE_FLAGS) -c -o $@ $<

$(BUILD)/release/$(SRC)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(RELEASE_CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

$(BUILD)/release/$(LIB)/%.o: $(LIB)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(RELEASE_CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<


# ------------------------------------------------------
# 					Running the debug build
# ------------------------------------------------------

# nftables requires root, and the private state directory must be owned by
# the user that runs the binary, so every run target uses the same SUDO
# command. Set SUDO= when already running as root.
SUDO ?= sudo
RUN_ARGS ?= --host 127.0.0.1 --port 8080
ADMIN_USER ?= admin

# Start the API.
run: debug
	@$(SUDO) ./$(TARGET) $(RUN_ARGS)

# Create the initial administrator interactively in OUT/.archangel-dev.
bootstrap-admin: debug
	@$(SUDO) ./$(TARGET) user bootstrap-admin --username $(ADMIN_USER)

# Write a default runtime config to OUT/.archangel-dev/config.json.
config: debug
	@$(SUDO) ./$(TARGET) config generate


# Target to clean up generated file; keeps OUT/.archangel-dev, which holds
# local accounts.
clean:
	@rm -rf $(BUILD) $(TARGET)

# Delete local accounts, sessions, config, and logs created by the run targets.
clean-dev-state:
	@$(SUDO) rm -rf $(OUT)/.archangel-dev
