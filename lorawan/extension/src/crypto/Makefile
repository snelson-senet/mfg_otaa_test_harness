export
.PHONY: all clean

$(info ------------------------------------------------------------)
$(info $(shell pwd) )
$(info ------------------------------------------------------------)

APP_NAME = crypto

CC := $(CROSS_COMPILE)gcc

SRCFILES += ./src/cmac.c  ./src/aes.c ./src/crypto.c $(COMMON_DIR)/src/utilities.c
SRCS     := $(notdir $(SRCFILES))
INCDIRS  += $(COMMON_DIR)/inc
VPATH     = $(dir $(SRCFILES))
OBJS     := $(foreach o, $(SRCS), $(addsuffix .o, $(basename $(join $(OBJ_DIR)/, $(notdir $(o))))))

DEPFLAGS = -MT $@ -MMD -MF $(DEP_DIR)/$*.Td

COMPILE.c = $(CC) $(CFLAGS) $(DEPFLAGS) $(WARN_FLAGS) $(DEBUG_FLAGS) $(foreach f, $(INCDIRS), -I $(f)) -c
POSTCOMPILE = mv -f $(DEP_DIR)/$*.Td $(DEP_DIR)/$*.d

TARGET := $(BIN_DIR)/$(APP_NAME).so

all: $(TARGET)

$(OBJ_DIR)/%.o : %.c
$(OBJ_DIR)/%.o : %.c $(DEP_DIR)/%.d
	@echo ---Start $(notdir $@) $(shell date)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)
	@echo ---Done  $(notdir $@) $(shell date)


$(TARGET) : $(OBJS)
	@echo ---Start $(notdir $@) $(shell date)
	$(CC) -shared $^  -o $@
	@echo ---Done  $(notdir $@) $(shell date)

print-% :
	@echo $* = $($*)

$(DEP_DIR)/%.d: ;
.PRECIOUS: $(DEP_DIR/%.d)
-include $(patsubst %,$(DEP_DIR)/%.d,$(basename $(SRCS)))

clean:
	rm -f $(TARGET)
	rm -f $(DEP_DIR)/*.d
	rm -f $(OBJ_DIR)/*.o



