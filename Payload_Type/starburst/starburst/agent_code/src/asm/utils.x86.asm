[BITS 32]

DEFAULT REL

GLOBAL _RipData
GLOBAL __alloca

[SECTION .text$B]
    ; _alloca - x86 stack probe + allocation
    ; Called with requested size in EAX
    ; Probes pages and sets ESP = original_ESP - SIZE
    ; Preserves ECX; clobbers EAX
    __alloca:
        push    ecx
        mov     ecx, esp
        add     ecx, 8              ; ecx = original ESP before call
    .loop:
        cmp     eax, 0x1000
        jb      .final
        sub     ecx, 0x1000
        or      dword [ecx], 0
        sub     eax, 0x1000
        jmp     .loop
    .final:
        sub     ecx, eax            ; ecx = original_ESP - SIZE (target)
        or      dword [ecx], 0
        mov     eax, esp            ; save old ESP
        mov     esp, ecx            ; ESP = target
        mov     ecx, [eax]          ; restore ecx from old stack
        push    dword [eax + 4]     ; push return address
        ret

[SECTION .text$C]
    _RipData:
        call _RetPtrData
    ret

    _RetPtrData:
        mov	eax, [esp]
        sub	eax, 0x5
    ret
