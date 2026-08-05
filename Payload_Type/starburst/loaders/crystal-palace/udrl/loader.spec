x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize
        dfr "resolve" "ror13"

        push $DLL
        preplen
        link "shellcode"

        export
