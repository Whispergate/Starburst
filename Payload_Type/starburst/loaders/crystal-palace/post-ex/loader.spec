x64:
    load "bin/loader-postex.x64.o"
        make pic +gofirst +optimize
        dfr "resolve" "ror13"

        push $DLL
        preplen
        link "shellcode"

        load %ARGFILE
            preplen
            link "sc_args"

        export

x86:
    load "bin/loader-postex.x86.o"
        make pic +gofirst +optimize
        dfr "resolve" "ror13"

        push $DLL
        preplen
        link "shellcode"

        load %ARGFILE
            preplen
            link "sc_args"

        export
