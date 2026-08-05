CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -c -Os -fno-asynchronous-unwind-tables -fpack-struct=8 -pipe -w
INCLUDES = -Iinclude

# Load mode: 0=VirtualAlloc, 1=Module Stomp
LOAD_MODE ?= 0
DEFINES   = -DLOAD_MODE=$(LOAD_MODE)

ifdef STOMP_DLL
DEFINES += -DSTOMP_DLL=\"$(STOMP_DLL)\"
endif

all: bin/loader.x64.o

bin/loader.x64.o: src/loader.c include/pic_defs.h include/user_data.h
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $<

clean:
	rm -f bin/loader.x64.o
