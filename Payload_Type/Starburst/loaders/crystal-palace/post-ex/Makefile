CC64  := x86_64-w64-mingw32-gcc
CC86  := i686-w64-mingw32-gcc
FLAGS := -c -Os -fno-asynchronous-unwind-tables -fpack-struct=8 -w

x64:
	$(CC64) $(FLAGS) -o bin/loader-postex.x64.o src/loader-postex.c

x86:
	$(CC86) $(FLAGS) -o bin/loader-postex.x86.o src/loader-postex.c

clean:
	rm -f bin/*.o
