x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize

        load %SHELLCODE
        preplen
        link "shellcode"

        export

x86:
    load "bin/loader.x86.o"
        make pic +gofirst +optimize

        load %SHELLCODE
        preplen
        link "shellcode"

        export
