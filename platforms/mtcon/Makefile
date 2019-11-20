export
.PHONY: all clean

PLAT_NAME :=mtcon
BUILD_DIR := $(TOP_DIR)/build/$(PLAT_NAME)
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin
DEP_DIR   := $(BUILD_DIR)/dep

################################################################################
# Tool Chain
################################################################################
TOOLS_DIR := /tools
PLATFORM_PATH := $(TOOLS_DIR)/toolchain/multitech/mlinux/3.3.9
CROSS_DIR     := $(PLATFORM_PATH)/sysroots/arm926ejste-mlinux-linux-gnueabi
CROSS_COMPILE := $(TOOLS_DIR)/toolchain/multitech/mlinux/3.3.9/sysroots/x86_64-mlinux-linux/usr/bin/arm-mlinux-linux-gnueabi/arm-mlinux-linux-gnueabi-
SYSROOT       := $(CROSS_DIR)
CC            := $(CROSS_COMPILE)gcc 
CFLAGS        += --sysroot=$(SYSROOT) -fPIC -shared 

################################################################################
# Build
################################################################################

$(info ============================================================)
$(info $(shell pwd) )
$(info ============================================================)

all: $(OBJ_DIR) $(BIN_DIR) $(DEP_DIR)
	$(MAKE) -C $(APP_DIR)/crypto

$(OBJ_DIR):
	@echo
	@echo $@
	mkdir -p $@

$(BIN_DIR):
	@echo
	@echo $@
	mkdir -p $@

$(DEP_DIR):
	@echo
	@echo $@
	mkdir -p $@

clean:
	$(MAKE) clean -C $(APP_DIR)/crypto
	

