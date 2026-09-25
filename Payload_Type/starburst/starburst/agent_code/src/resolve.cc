#include <common.h>
#include <native.h>

/*!
 * @brief
 *  searching for the library base address
 *  based on the fvna1 name hash
 *
 * @param library_hash
 *  fnva1 hash of the library name
 *
 * @return
 *  return the base address of the module
 */
auto declfn resolve::module(
   _In_ const uint32_t library_hash
) -> uintptr_t {
    //
    // iterate over the linked list
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !library_hash ) {
            return reinterpret_cast<uintptr_t>( Entry->DllBase );
        }

        if ( stardust::hash_string<wchar_t>( Entry->BaseDllName.Buffer ) == library_hash ) {
            return reinterpret_cast<uintptr_t>( Entry->DllBase ); 
        }
    } )

    return 0;
}

/*!
 * @brief
 *  resolve function symbol
 *  from specified module
 *
 * @param module_base
 *  module to resolve api from
 *
 * @param symbol_hash
 *  symbol name hash to resolve
 *
 * @return
 *  symbol function pointer
 */
auto declfn resolve::_api(
    _In_ const uintptr_t module_base,
    _In_ const uintptr_t symbol_hash
) -> uintptr_t {
    auto address      = uintptr_t { 0 };
    auto nt_header    = PIMAGE_NT_HEADERS { nullptr };
    auto dos_header   = PIMAGE_DOS_HEADER { nullptr };
    auto export_dir   = PIMAGE_EXPORT_DIRECTORY { nullptr };
    auto export_names = PDWORD { nullptr };
    auto export_addrs = PDWORD { nullptr };
    auto export_ordns = PWORD { nullptr };
    auto symbol_name  = PSTR { nullptr };

    dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>( module_base );
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>( module_base + dos_header->e_lfanew );
    if ( nt_header->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    auto exp_va   = nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    auto exp_size = nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

    export_dir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( module_base + exp_va );
    export_names = reinterpret_cast<PDWORD>( module_base + export_dir->AddressOfNames );
    export_addrs = reinterpret_cast<PDWORD>( module_base + export_dir->AddressOfFunctions );
    export_ordns = reinterpret_cast<PWORD> ( module_base + export_dir->AddressOfNameOrdinals );

    for ( int i = 0; i < export_dir->NumberOfNames; i++ ) {
        symbol_name = reinterpret_cast<PSTR>( module_base + export_names[ i ] );

        if ( stardust::hash_string( symbol_name ) != symbol_hash ) {
            continue;
        }

        auto rva = export_addrs[ export_ordns[ i ] ];

        if ( rva >= exp_va && rva < exp_va + exp_size ) {
            auto fwd_str = reinterpret_cast<const char*>( module_base + rva );
            char fwd_dll[140] = { 0 };
            int  dot_pos = -1;

            for ( int j = 0; fwd_str[j] && j < 127; j++ ) {
                fwd_dll[j] = fwd_str[j];
                if ( fwd_str[j] == '.' ) {
                    dot_pos = j;
                    break;
                }
            }

            if ( dot_pos < 0 ) return 0;

            fwd_dll[dot_pos    ] = '.';
            fwd_dll[dot_pos + 1] = 'd';
            fwd_dll[dot_pos + 2] = 'l';
            fwd_dll[dot_pos + 3] = 'l';
            fwd_dll[dot_pos + 4] = '\0';

            auto fwd_func = fwd_str + dot_pos + 1;
            auto func_hash = stardust::hash_string( fwd_func );

            auto fwd_base = resolve::module( stardust::hash_string( fwd_dll ) );

            if ( !fwd_base && fwd_dll[0] == 'a' && fwd_dll[1] == 'p' && fwd_dll[2] == 'i' && fwd_dll[3] == '-' ) {
                char kb[] = { 'k','e','r','n','e','l','b','a','s','e','.','d','l','l',0 };
                fwd_base = resolve::module( stardust::hash_string( kb ) );
                if ( !fwd_base ) {
                    char nt[] = { 'n','t','d','l','l','.','d','l','l',0 };
                    fwd_base = resolve::module( stardust::hash_string( nt ) );
                }
            }

            if ( !fwd_base ) {
                char k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
                auto k32_base = resolve::module( stardust::hash_string( k32 ) );
                if ( k32_base ) {
                    char lla[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
                    auto pLLA = reinterpret_cast<HMODULE(WINAPI*)(LPCSTR)>(
                        _api( k32_base, stardust::hash_string( lla ) ) );
                    if ( pLLA ) {
                        auto hMod = pLLA( fwd_dll );
                        if ( hMod )
                            fwd_base = reinterpret_cast<uintptr_t>( hMod );
                    }
                }
            }

            if ( !fwd_base ) return 0;

            return _api( fwd_base, func_hash );
        }

        address = module_base + rva;
        break;
    }

    return address;
}

auto declfn resolve::GetModuleHandleH(
    _In_ uint32_t uDllNameHash,
    _In_ fnStringHashingFunction pStringHashingFunc
) -> HMODULE {

    auto pPeb     = NtCurrentPeb();
    auto pLdrData = pPeb->Ldr;
    auto pEntry   = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
                        pLdrData->InMemoryOrderModuleList.Flink );

    if ( uDllNameHash && !pStringHashingFunc )
        return nullptr;

    if ( !uDllNameHash )
        return reinterpret_cast<HMODULE>( pEntry->InInitializationOrderLinks.Flink );

    while ( pEntry->FullDllName.Buffer ) {

        if ( pEntry->FullDllName.Length > 0 && pEntry->FullDllName.Length < MAX_PATH ) {

            char cUprDllFileName[MAX_PATH] = {};

            for ( USHORT i = 0; i < pEntry->FullDllName.Length && i < MAX_PATH - 1; i++ ) {
                auto c = static_cast<char>( pEntry->FullDllName.Buffer[i] );
                if ( c >= 'a' && c <= 'z' )
                    cUprDllFileName[i] = c - 'a' + 'A';
                else
                    cUprDllFileName[i] = c;
            }

            if ( pStringHashingFunc( cUprDllFileName ) == uDllNameHash )
                return reinterpret_cast<HMODULE>( pEntry->InInitializationOrderLinks.Flink );
        }

        pEntry = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>( pEntry );
    }

    return nullptr;
}

auto declfn resolve::GetProcAddressH(
    _In_ HMODULE hModule,
    _In_ uint32_t uApiHash,
    _In_ fnStringHashingFunction pStringHashingFunc
) -> FARPROC {

    auto pBase = reinterpret_cast<PBYTE>( hModule );

    if ( !hModule || !uApiHash || !pStringHashingFunc )
        return nullptr;

    auto pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(
        pBase + reinterpret_cast<PIMAGE_DOS_HEADER>( pBase )->e_lfanew );
    if ( pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE )
        return nullptr;

    auto pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    auto dwImgExportDirSize = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    auto pdwFunctionNameArray    = reinterpret_cast<PDWORD>( pBase + pImgExportDir->AddressOfNames );
    auto pdwFunctionAddressArray = reinterpret_cast<PDWORD>( pBase + pImgExportDir->AddressOfFunctions );
    auto pwFunctionOrdinalArray  = reinterpret_cast<PWORD> ( pBase + pImgExportDir->AddressOfNameOrdinals );

    if ( uApiHash <= 0xFFFF ) {
        WORD wOrdinal = static_cast<WORD>( uApiHash );
        if ( wOrdinal < pImgExportDir->Base ||
             wOrdinal >= pImgExportDir->Base + pImgExportDir->NumberOfFunctions )
            return nullptr;
        return reinterpret_cast<FARPROC>( pBase + pdwFunctionAddressArray[wOrdinal - pImgExportDir->Base] );
    }

    for ( DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++ ) {

        auto pFunctionName    = reinterpret_cast<char*>( pBase + pdwFunctionNameArray[i] );
        auto pFunctionAddress = reinterpret_cast<PVOID>( pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]] );

        if ( pStringHashingFunc( pFunctionName ) == uApiHash ) {

            if ( reinterpret_cast<uintptr_t>( pFunctionAddress ) >= reinterpret_cast<uintptr_t>( pImgExportDir ) &&
                 reinterpret_cast<uintptr_t>( pFunctionAddress ) <  reinterpret_cast<uintptr_t>( pImgExportDir ) + dwImgExportDirSize ) {

                char  cForwarderName[MAX_PATH] = {};
                DWORD dwDotOffset              = 0;

                auto pForwarder = reinterpret_cast<const char*>( pFunctionAddress );
                for ( DWORD j = 0; pForwarder[j] && j < MAX_PATH - 1; j++ ) {
                    cForwarderName[j] = pForwarder[j];
                    if ( pForwarder[j] == '.' ) {
                        dwDotOffset        = j;
                        cForwarderName[j]  = '\0';
                    }
                }

                auto pcFunctionMod  = cForwarderName;
                auto pcFunctionName = cForwarderName + dwDotOffset + 1;

                HMODULE hFwdModule = GetModuleHandleH(
                    pStringHashingFunc( pcFunctionMod ), pStringHashingFunc );

                if ( !hFwdModule )
                    return nullptr;

                return GetProcAddressH( hFwdModule, pStringHashingFunc( pcFunctionName ), pStringHashingFunc );
            }

            return reinterpret_cast<FARPROC>( pFunctionAddress );
        }
    }

    return nullptr;
}
