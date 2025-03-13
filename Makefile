NAME   := stardust

CCX64  := clang -target x86_64-w64-mingw32
CCX86  := clang -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -s -w -mno-sse
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -fPIC -Iinclude -Wl,-Tscripts/linker.ld

SRC    := $(wildcard src/*.cc)
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
	@ $(CCX64) bin/obj/*.x64.obj -o bin/$(NAME).x64.exe $(CFLAGS)
	@ python scripts/extract.py -f bin/$(NAME).x64.exe -o bin/$(NAME).x64.bin
	@ rm bin/$(NAME).x64.exe

x86: nasm86 $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) bin/obj/*.x86.obj -o bin/$(NAME).x86.exe $(CFLAGS)
	@ python scripts/extract.py -f bin/$(NAME).x86.exe -o bin/$(NAME).x86.bin
	@ rm bin/$(NAME).x86.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o bin/obj/$(notdir $@) -c $< $(CFLAGS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o bin/obj/$(notdir $@) -c $< $(CFLAGS)

nasm64:
	@ $(ASMCC) -f win64 src/asm/entry.x64.asm -o bin/obj/entry.x64.obj
	@ $(ASMCC) -f win64 src/asm/utils.x64.asm -o bin/obj/utils.x64.obj

nasm86:
	@ $(ASMCC) -f win32 src/asm/entry.x86.asm -o bin/obj/entry.x86.obj
	@ $(ASMCC) -f win32 src/asm/utils.x86.asm -o bin/obj/utils.x86.obj

stomper:
	@ $(CCX64) test/stomper.cc -o test/stomper.x64.exe -w
	@ $(CCX86) test/stomper.cc -o test/stomper.x86.exe -w

clean:
	@ rm -f bin/obj/*.x64.obj
	@ rm -f bin/obj/*.x86.obj
	@ rm -f bin/*.exe
	@ rm -f bin/*.bin
	@ echo "removed object files"
