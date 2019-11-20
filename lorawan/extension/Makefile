export
MAKEFLAGS += --no-print-directory

.PHONY: x86_64 armv5tej1

TOP_DIR    := $(shell pwd)
PLAT_DIR   := $(TOP_DIR)/platforms
SRC_DIR    := $(TOP_DIR)/src
COMMON_DIR := $(SRC_DIR)/common

all: x86_64 armv5tej1

x86_64:
	make all -C $(PLAT_DIR)/x86_64

armv5tej1:
	make all -C $(PLAT_DIR)/armv5tej1

clean:
	$(MAKE) clean -C $(PLAT_DIR)/x86_64
	$(MAKE) clean -C $(PLAT_DIR)/armv5tej1
