export
MAKEFLAGS += --no-print-directory

.PHONY: x86_64 armv5tejl

TOP_DIR    := $(shell pwd)
PLAT_DIR   := $(TOP_DIR)/platforms
SRC_DIR    := $(TOP_DIR)/src
COMMON_DIR := $(SRC_DIR)/common

all: x86_64 armv5tejl

x86_64:
	make all -C $(PLAT_DIR)/x86_64

armv5tejl:
	make all -C $(PLAT_DIR)/armv5tejl

clean:
	$(MAKE) clean -C $(PLAT_DIR)/x86_64
	$(MAKE) clean -C $(PLAT_DIR)/armv5tejl
