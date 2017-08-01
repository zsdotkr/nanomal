######################################################################################
#
######################################################################################

DEPEND = #_zslib.h zslib.h
OBJ_DIR 		= objs
OUTPUT			= zslib.a
CFLAGS			= -m64 -malign-double 
CC				= gcc
AR				= ar
RANLIB			= ranlib

USER_OBJS = $(OBJ_DIR)/ip.o $(OBJ_DIR)/common.o

#-----------------------------------------------------------------

CFLAGS += -Wall -g -O2 -Wno-int-to-pointer-cast -pthread -D_GNU_SOURCE -Wno-strict-aliasing -Wno-unused

$(OUTPUT): $(USER_OBJS) $(DEPEND)
	@\rm -f core core.*
	@\rm -f $@
	@$(AR) -r $@ $(USER_OBJS)
	@$(RANLIB) $@

clean:	
	@rm -f core core.*
	@if [ -d $(OBJ_DIR) ]; then \rm -fR $(OBJ_DIR);	fi
	@rm -fR objs*
	@rm -f *.a

$(OBJ_DIR)/%.o: %.c $(DEPEND)
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR);	fi
	@\rm -f $@
	$(CC) $(CFLAGS) -c $< -o $@ 

