[BITS 32]

DEFAULT REL

GLOBAL _RipData
GLOBAL __alloca

[SECTION .text$B]
    ; _alloca - x86 stack probe + allocation
    ; Called with requested size in EAX
    ; Must probe pages and adjust ESP, preserving return address
    ; Clobbers nothing except EAX (which becomes the new stack pointer)
    __alloca:
        push    ecx                 ; save ecx
        mov     ecx, esp            ; ecx = current ESP (after push ecx)
        add     ecx, 8              ; ecx = original ESP before call (skip saved ecx + ret addr)
    .loop:
        cmp     eax, 0x1000
        jb      .final
        sub     ecx, 0x1000
        or      dword [ecx], 0     ; probe page (read-modify-write)
        sub     eax, 0x1000
        jmp     .loop
    .final:
        sub     ecx, eax            ; subtract remaining bytes
        or      dword [ecx], 0     ; probe final page
        mov     eax, [esp]          ; restore ecx value
        mov     [ecx], eax          ; store ecx at new stack location
        mov     eax, [esp + 4]      ; get return address
        mov     [ecx + 4], eax      ; place return address at new stack
        lea     esp, [ecx]          ; set new stack pointer
        pop     ecx                 ; restore ecx
        ret                         ; return to caller with adjusted stack

[SECTION .text$C]
    _RipData:
        call _RetPtrData
    ret

    _RetPtrData:
        mov	eax, [esp]
        sub	eax, 0x5
    ret
