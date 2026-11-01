[BITS 32]

DEFAULT REL

EXTERN _entry
GLOBAL _stardust
GLOBAL _RipStart

[SECTION .text$A]
    _stardust:
        jmp short .code
    .ftbl_off:
        dd 0                                ; fixup table offset, patched by gen_fixups.py

    .code:
        push ebp
        mov  ebp, esp
        push edi
        push esi

        ; compute base address -> EDI
        call .getpc
    .getpc:
        pop  edi
        sub  edi, (.getpc - _stardust)      ; edi = runtime address of _stardust

        ; read fixup table offset from _stardust+2
        mov  eax, [edi + 2]
        test eax, eax
        jz   .no_fixup

        ; apply dir32 fixups
        lea  esi, [edi + eax]               ; esi = fixup table base
        mov  ecx, [esi]                     ; ecx = count
        add  esi, 4
    .fixloop:
        test ecx, ecx
        jz   .no_fixup
        mov  edx, [esi]                     ; offset of value to fix
        add  [edi + edx], edi               ; *(BASE + offset) += BASE
        add  esi, 4
        dec  ecx
        jmp  .fixloop

    .no_fixup:
        pop  esi
        pop  edi
        call _entry
        mov  esp, ebp
        pop  ebp
    ret

    _RipStart:
        call _RipPtr
    .rip_ret:
    ret

    _RipPtr:
        mov eax, [esp]
        sub eax, (_RipStart.rip_ret - _stardust)
    ret
