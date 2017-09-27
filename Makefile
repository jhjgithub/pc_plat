#
#     Filename: Makefile
#  Description: Standalone makefile for packet classification platform
#
#       Author: Xiang Wang (xiang.wang.s@gmail.com)
#
# Organization: Network Security Laboratory (NSLab),
#               Research Institute of Information Technology (RIIT),
#               Tsinghua University (THU)
#

INC_DIR = inc
SRC_DIR = src
BIN_DIR = bin

#rwildcard = $(foreach d, $(wildcard $1*), $(call rwildcard, $d/, $2) $(filter $(subst *, %, $2), $d))

SRC=src/clsfy/hypersplit.c 
SRC+=src/common/point_range.c src/common/utils.c src/common/mpool.c 
SRC+=src/common/rule_trace.c src/common/impl.c src/common/sort.c
SRC+=src/group/rfg.c src/pc_plat.c

HEADERS=./inc/common/impl.h ./inc/common/rule_trace.h ./inc/common/mpool.h
HEADERS+=./inc/common/point_range.h ./inc/common/utils.h ./inc/common/buffer.h
HEADERS+=./inc/common/sort.h ./inc/group/rfg.h ./inc/clsfy/hypersplit.h

#SRC = $(call rwildcard, $(SRC_DIR)/, *.c)
DEP = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.d, $(SRC))
OBJ = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRC))
BIN = $(BIN_DIR)/pc_plat

CC = gcc
CFLAGS = -Wall -g -I$(INC_DIR)/
#CFLAGS = -Wall -O2 -DNDEBUG -I$(INC_DIR)/

all: $(BIN) run_pc

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(SRC_DIR)/%.s: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -S -o $@ $<

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR)/%.d: $(SRC_DIR)/%.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

$(BIN): $(OBJ)
	$(CC) -o $@ $^ -lrt

clean:
	rm -rf $(BIN_DIR);

tag:
	ctags -R

run_grp:
	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K

run_pc:
#	./bin/pc_plat -p hs -f wustl_g -r rule_trace/rules/rfg/fw1_10K -t rule_trace/traces/origin/fw1_10K_trace
#	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K
#	./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/acl1_10K -t rule_trace/traces/origin/acl1_10K_trace
#	./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/fw1_10K -t rule_trace/traces/origin/fw1_10K_trace
	./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace
#	gdb -ex=r --args ./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace

format: $(SRC) $(HEADERS)
	 uncrustify --no-backup --mtime -c ./formatter.cfg $^
