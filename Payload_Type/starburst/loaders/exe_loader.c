%ENGINE_DEFINES%
#include "engine.h"

static unsigned char shellcode[] = { %SHELLCODE_BYTES% };
static unsigned int shellcode_len = %SHELLCODE_LEN%;

int main(void) {
    return engine_run(shellcode, shellcode_len) ? 0 : 1;
}
