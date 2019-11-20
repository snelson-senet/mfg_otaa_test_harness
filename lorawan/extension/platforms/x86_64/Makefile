export
.PHONY: all clean

PLAT_NAME :=x86_64
BUILD_DIR := $(TOP_DIR)/build/$(PLAT_NAME)
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin
DEP_DIR   := $(BUILD_DIR)/dep

CFLAGS += -fPIC -shared 

################################################################################
# Build
################################################################################

$(info ============================================================)
$(info $(shell pwd) )
$(info ============================================================)

all: $(OBJ_DIR) $(BIN_DIR) $(DEP_DIR)
	$(MAKE) -C $(SRC_DIR)/crypto

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
	$(MAKE) clean -C $(SRC_DIR)/crypto
	

