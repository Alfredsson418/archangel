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
LDFLAGS = -lnftables -pthread
# lm is used by argtable3


# Get all the source files in the SRC directory and its subdirectories
SRCFILES = $(shell find $(SRC) -name '*.cpp')
LIB_SRCFILES = $(shell find $(LIB) -name '*.cpp')


# Generate object file names from source file names
OBJFILES = $(patsubst $(SRC)/%.cpp, $(BUILD)/$(SRC)/%.o, $(SRCFILES))
LIB_OBJFILES = $(patsubst $(LIB)/%.cpp, $(BUILD)/$(LIB)/%.o, $(LIB_SRCFILES))

.PHONY: debug release clean FORCE

FORCE:

$(VERSION_HEADER): FORCE
	@mkdir -p $(@D)
	@printf '#pragma once\n#define ARCHANGEL_GIT_COMMIT "%s"\n' "$(GIT_COMMIT)" > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

$(BUILD)/$(SRC)/http/server.o: $(VERSION_HEADER)

# Target to build the executable with debug flags
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(OBJFILES) $(LIB_OBJFILES)
	@echo "Building $(NAME) in debug mode"
	@$(CC) $(CFLAGS) $^ -o $(NAME) $(LDFLAGS)
	@echo "Done!"


# Target to build the executable with release flags
build_release: CFLAGS = $(RELEASE_CFLAGS)
build_release: $(OBJFILES) $(LIB_OBJFILES)
	@echo "Building $(NAME) in release mode"
	@$(CC) $(CFLAGS) $^ -o $(NAME) $(LDFLAGS)
	@echo "Done!"

# Rule to compile each source file into an object file
$(BUILD)/$(SRC)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -I$(BUILD)/generated -c -o $@ $<

$(BUILD)/$(LIB)/%.o: $(LIB)/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -I$(BUILD)/generated -c -o $@ $<


# Target to clean up generated file
clean:
	@rm -rf $(BUILD) $(NAME)
