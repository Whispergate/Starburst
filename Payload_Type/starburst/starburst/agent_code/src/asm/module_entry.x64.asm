[BITS 64]
DEFAULT REL

EXTERN module_init

GLOBAL stardust
GLOBAL RipStart

[SECTION .text$A]

stardust:
    jmp module_init

RipStart:
    call RipStartHelper

RipStartRet:
    ret

RipStartHelper:
    mov rax, [rsp]
    sub rax, (RipStartRet - stardust)
    ret
