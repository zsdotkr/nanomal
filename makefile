CC      = gcc
CFLAGS  = -g -I/usr/include -I/usr/include/pcap -Izslib
CFLAGS += -Wall  -pthread -O2 -Wno-unused-variable# -Wwrite-strings # -Wstrict-prototypes
LD      = -lpcap zslib/zslib.a
OBJ_DIR = objs

USER_OBJS = $(OBJ_DIR)/sklist.o $(OBJ_DIR)/main.o

DEPEND = decode.h

all:  test

test: $(USER_OBJS) $(DEPEND) 
	@\rm -f core core.* 
	@\rm -f $@
	$(CC) $(CFLAGS) -o $@ $(USER_OBJS) $(LD) 

clean:
	@\rm -f core core.* 
	@if [ -d $(OBJ_DIR) ]; then \rm -fR $(OBJ_DIR); fi 
	@\rm -f test

$(OBJ_DIR)/%.o: %.c $(DEPEND) 
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi 
	@\rm -f $@
	$(CC) $(CFLAGS) -c $< -o $@
