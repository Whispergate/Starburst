NAME   := starburst

CCX64  := clang -target x86_64-w64-mingw32
CCX86  := clang -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -s -w -mno-sse
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 -fno-jump-tables
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -Iinclude -Wl,-Tscripts/linker.ld

# Detect mingw-w64 C++ headers for cross-compilation (clang often can't find them)
# Linux: headers under /usr/lib/gcc/<triple>/*/include/c++
GCC_X64_CXX := $(wildcard /usr/lib/gcc/x86_64-w64-mingw32/*/include/c++)
GCC_X86_CXX := $(wildcard /usr/lib/gcc/i686-w64-mingw32/*/include/c++)
ifneq ($(GCC_X64_CXX),)
  GCC_X64_DIR := $(firstword $(GCC_X64_CXX))
  GCC_X64_VER := $(patsubst /usr/lib/gcc/x86_64-w64-mingw32/%/include/c++,%,$(GCC_X64_DIR))
  CFLAGS_X64_INC := -isystem $(GCC_X64_DIR) -isystem $(GCC_X64_DIR)/x86_64-w64-mingw32
endif
ifneq ($(GCC_X86_CXX),)
  GCC_X86_DIR := $(firstword $(GCC_X86_CXX))
  GCC_X86_VER := $(patsubst /usr/lib/gcc/i686-w64-mingw32/%/include/c++,%,$(GCC_X86_DIR))
  CFLAGS_X86_INC := -isystem $(GCC_X86_DIR) -isystem $(GCC_X86_DIR)/i686-w64-mingw32
endif

# MSYS2/Windows: clang can't find mingw sysroot - point it at MSYS2 directories
MSYS2_X64_HDR := $(wildcard C:/msys64/mingw64/include/windows.h)
MSYS2_X86_HDR := $(wildcard C:/msys64/mingw32/include/windows.h)
MSYS2_X64_CXX := $(wildcard C:/msys64/mingw64/include/c++/*)
MSYS2_X86_CXX := $(wildcard C:/msys64/mingw32/include/c++/*)
ifneq ($(MSYS2_X64_HDR),)
  ifeq ($(CFLAGS_X64_INC),)
    CFLAGS_X64_INC := --sysroot=C:/msys64/mingw64
    ifneq ($(MSYS2_X64_CXX),)
      CFLAGS_X64_INC += -isystem $(firstword $(MSYS2_X64_CXX)) -isystem $(firstword $(MSYS2_X64_CXX))/x86_64-w64-mingw32
    endif
  endif
endif
ifneq ($(MSYS2_X86_HDR),)
  ifeq ($(CFLAGS_X86_INC),)
    CFLAGS_X86_INC := --sysroot=C:/msys64/mingw32
    ifneq ($(MSYS2_X86_CXX),)
      CFLAGS_X86_INC += -isystem $(firstword $(MSYS2_X86_CXX)) -isystem $(firstword $(MSYS2_X86_CXX))/i686-w64-mingw32
    endif
  endif
endif

GCC_TOOLCHAIN ?=
ifneq ($(GCC_TOOLCHAIN),)
CFLAGS += --gcc-toolchain=$(GCC_TOOLCHAIN)
endif

DEFINES ?=
CFLAGS  += $(DEFINES)

SRC    := $(wildcard src/*.cc) $(wildcard src/commands/*.cc) $(wildcard src/transport/*.cc) $(wildcard src/evasion/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj)
OBJ86  := $(SRC:%.cc=%.x86.obj)

release: x64 x86
debug: 	 x64-debug x86-debug

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
x86-debug: x86

x64: nasm64 $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) bin/obj/*.x64.obj -o bin/$(NAME).x64.exe $(CFLAGS) $(CFLAGS_X64_INC)
	@ objcopy --dump-section .text=bin/$(NAME).x64.bin bin/$(NAME).x64.exe

x86: nasm86 $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) bin/obj/*.x86.obj -o bin/$(NAME).x86.exe $(CFLAGS) $(CFLAGS_X86_INC)
	@ objcopy --dump-section .text=bin/$(NAME).x86.bin bin/$(NAME).x86.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o bin/obj/$(notdir $@) -c $< $(CFLAGS) $(CFLAGS_X64_INC)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o bin/obj/$(notdir $@) -c $< $(CFLAGS) $(CFLAGS_X86_INC)

nasm64:
	@ $(ASMCC) -f win64 src/asm/entry.x64.asm -o bin/obj/entry.x64.obj
	@ $(ASMCC) -f win64 src/asm/utils.x64.asm -o bin/obj/utils.x64.obj
	@ $(ASMCC) -f win64 src/asm/draugr.x64.asm -o bin/obj/draugr.x64.obj

nasm86:
	@ $(ASMCC) -f win32 src/asm/entry.x86.asm -o bin/obj/entry.x86.obj
	@ $(ASMCC) -f win32 src/asm/utils.x86.asm -o bin/obj/utils.x86.obj

stomper:
	@ $(CCX64) test/stomper.cc -o test/stomper.x64.exe -w
	@ $(CCX86) test/stomper.cc -o test/stomper.x86.exe -w

# ── PIC Module building ─────────────────────────────────────────
MODULE_DIR     := bin/modules
MODULE_HELPERS := src/parser.cc src/package.cc src/strings.cc src/heap.cc \
                  src/base64.cc src/intrinsics.cc src/resolve.cc src/crypto.cc

# Commands excluded from module builds (core + multi-handler sources)
MOD_EXCLUDE := cmd_load.cc cmd_exit.cc cmd_sleep.cc cmd_config.cc \
               cmd_upload.cc cmd_download.cc cmd_spawnto.cc \
               cmd_wmiexec.cc cmd_dcomexec.cc

MOD_CMD_SRC := $(filter-out $(addprefix src/commands/,$(MOD_EXCLUDE)), \
               $(wildcard src/commands/cmd_*.cc))

modules-x64:
	@ mkdir -p $(MODULE_DIR)
	@ echo "[modules] assembling entry + utils"
	@ $(ASMCC) -f win64 src/asm/module_entry.x64.asm -o $(MODULE_DIR)/module_entry.x64.obj
	@ $(ASMCC) -f win64 src/asm/utils.x64.asm -o $(MODULE_DIR)/utils.x64.obj
	@ for h in $(MODULE_HELPERS); do \
	    b=$$(basename $$h .cc); \
	    echo "  [mod-helper] $$b"; \
	    $(CCX64) -c $$h -o $(MODULE_DIR)/$$b.x64.obj $(CFLAGS) $(CFLAGS_X64_INC); \
	  done
	@ HOBJS=""; for h in $(MODULE_HELPERS); do \
	    b=$$(basename $$h .cc); \
	    HOBJS="$$HOBJS $(MODULE_DIR)/$$b.x64.obj"; \
	  done; \
	  for src in $(MOD_CMD_SRC); do \
	    name=$$(basename $$src .cc | sed 's/^cmd_//'); \
	    upper=$$(echo $$name | tr 'a-z' 'A-Z'); \
	    echo "  [module] $$name"; \
	    $(CCX64) -c $$src -o $(MODULE_DIR)/cmd_$$name.x64.obj \
	      $(CFLAGS) $(CFLAGS_X64_INC) -DINCLUDE_CMD_$$upper 2>/dev/null && \
	    $(CCX64) -c modules/module_init_template.cc -o $(MODULE_DIR)/init_$$name.x64.obj \
	      $(CFLAGS) $(CFLAGS_X64_INC) -DINCLUDE_CMD_$$upper \
	      -DMODULE_CMD_ID=CMD_$$upper -DMODULE_NAME=$$name 2>/dev/null && \
	    $(CCX64) \
	      $(MODULE_DIR)/module_entry.x64.obj \
	      $(MODULE_DIR)/init_$$name.x64.obj \
	      $(MODULE_DIR)/cmd_$$name.x64.obj \
	      $$HOBJS $(MODULE_DIR)/utils.x64.obj \
	      -o $(MODULE_DIR)/$$name.x64.exe $(CFLAGS) $(CFLAGS_X64_INC) 2>/dev/null && \
	    objcopy --dump-section .text=$(MODULE_DIR)/$$name.x64.raw $(MODULE_DIR)/$$name.x64.exe && \
	    printf '\x00\x00\x00\x00' | cat - $(MODULE_DIR)/$$name.x64.raw > $(MODULE_DIR)/$$name.x64.bin && \
	    rm -f $(MODULE_DIR)/$$name.x64.raw $(MODULE_DIR)/$$name.x64.exe && \
	    echo "    -> $$name.x64.bin" || \
	    echo "    [SKIP] $$name (build failed)"; \
	  done
	@ echo "[modules] done"

clean:
	@ rm -f bin/obj/*.x64.obj
	@ rm -f bin/obj/*.x86.obj
	@ rm -f bin/modules/*
	@ rm -f bin/*.exe
	@ rm -f bin/*.bin
	@ echo "removed object files"
