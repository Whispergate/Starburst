[BITS 64]

DEFAULT REL

GLOBAL RipData
GLOBAL ___chkstk_ms
GLOBAL __chkstk_ms

[SECTION .text$B]
    ___chkstk_ms:
    __chkstk_ms:
        push    rcx
        push    rax
        cmp     rax, 0x1000
        lea     rcx, [rsp + 0x18]
        jb      .cs_done
    .cs_loop:
        sub     rcx, 0x1000
        test    dword [rcx], eax
        sub     rax, 0x1000
        cmp     rax, 0x1000
        ja      .cs_loop
    .cs_done:
        pop     rax
        pop     rcx
        ret

[SECTION .text$C]
    RipData:
        call RetPtrData
    ret

    RetPtrData:
        mov	rax, [rsp]
        sub	rax, 0x5
    ret