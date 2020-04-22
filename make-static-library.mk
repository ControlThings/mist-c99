#
# Makefile for generating static library which can then be used as a
# part in the node.js shared library, for example.
#
# This makefile is designed to be used via an build script which sets up
# make variables.
#
# The interface is the following, these variables must be set by build script:
#
# CC            The C compiler
# APPEND_CFLAGS	CFLAGS to be appended last, intended for e.g. architecture-specific flags.
#		See note about CFLAGS below (optional)
# BUILD_TYPE    Defines the build type, currently only
#               "nodejs_plugin" is supporte
# BUILD_FLAVOUR "release" or "debug"
# VERBOSE       Can be set to 1, to see the actual invocations
# 
# If you need to override CFLAGS, you must supply all CFLAGS. 
# If you override a variable from commandline, all the assignments to that 
# variable in the makefile will be overriden!

# The build dir
BUILD_BASE	= build

# name for the target artifact
TARGET	= libmist.a

# which modules (subdirectories) of the project to include in compiling
MODULES		= src wish wish_app_deps wish_app_port_deps/unix wish_app deps/wish-rpc-c99/src apps/mist-standalone deps/mbedtls/library deps/ed25519/src ed25519/src deps/bson 
EXTRA_INCDIR    = wish wish_app_deps deps/libuv/include deps/mbedtls/include deps/wish-rpc-c99/src deps/bson deps/ed25519/src deps/uthash/include

# General CFLAGS, common to all builds
CFLAGS		= -Wall -ffunction-sections -fdata-sections -Wno-pointer-sign -Werror -Wno-unused-function -Wno-unused-variable -Wno-unused-result
CFLAGS         += -DMIST_API_VERSION_STRING=\"$(shell git describe --abbrev=4 --dirty --always --tags)\"

ifeq ($(BUILD_TYPE), nodejs_plugin)
# ...then CFLAGS related to node.js plugin build..."
CFLAGS += -fvisibility=hidden -fPIC -pthread -MD -DSTDC_HEADERS -DHAVE_STDLIB_H -DENABLE_PTHREAD 
CFLAGS += -DMIST_API_COMMISSION_TIME_SCALE=50
CFLAGS += -DMIST_API_MAX_UIDS=2048
CFLAGS += -DNUM_WISH_APPS=100
CFLAGS += -DNUM_MIST_APPS=100
endif

# Finally, CFLAGS related to debug / release build
ifeq ($(BUILD_FLAVOUR), release)
CFLAGS          += -O2 -DRELEASE_BUILD
else
CFLAGS           += -g -O0
endif

CFLAGS += $(APPEND_CFLAGS)

# Useful printouts for Makefile debugging:
#$(info BUILD_TYPE is $(BUILD_TYPE) and flavour is $(BUILD_FLAVOUR))
$(info CFLAGS is $(CFLAGS))

# ASM flags
ASFLAGS     = -MD 

# linker flags used to generate the main object file
LDFLAGS		= -pthread
LDLIBS		= -lpthread -lrt

# select which tools to use as compiler, librarian and linker. These will be overriden by Make invocation
CC		:= gcc
AR		:= ar
LD		:=
SIZE	:=

####
#### no user configurable options below here
####
SRC_DIR		:= $(MODULES)
BUILD_DIR	:= $(addprefix $(BUILD_BASE)/,$(MODULES))

SRC		:= $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ		:= $(patsubst %.c,$(BUILD_BASE)/%.o,$(SRC))
LIBS		:= $(addprefix -l,$(LIBS))

INCDIR	:= $(addprefix -I,$(SRC_DIR))
EXTRA_INCDIR	:= $(addprefix -I,$(EXTRA_INCDIR))

V ?= $(VERBOSE)
ifeq ("$(V)","1")
Q :=
vecho := @true
else
Q := @
vecho := @echo
endif

vpath %.c $(SRC_DIR)

define compile-objects
$1/%.o: %.c
	$(vecho) "CC $$<"
	$(Q) $(CC) $(INCDIR) $(MODULE_INCDIR) $(EXTRA_INCDIR) $(SDK_INCDIR) $(CFLAGS) -c $$< -o $$@
endef

.PHONY: all checkdirs clean

all: clean checkdirs $(TARGET)

noclean:  checkdirs $(TARGET)

$(TARGET): $(OBJ)
	$(AR) rcs $@ $^

checkdirs: $(BUILD_DIR) 

$(BUILD_DIR):
	$(Q) mkdir -p $@

clean:
	$(Q) rm -rf $(TARGET) $(BUILD_BASE)

$(foreach bdir,$(BUILD_DIR),$(eval $(call compile-objects,$(bdir))))
