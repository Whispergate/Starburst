#ifndef STARBURST_SSH_CLIENT_H
#define STARBURST_SSH_CLIENT_H

#include <macros.h>

#ifdef INCLUDE_CMD_SSH

#define SSH_MAX_SESSIONS        4
#define SSH_RECV_BUF_SIZE       65536
#define SSH_MAX_PACKET_SIZE     35000
#define SSH_CHANNEL_WINDOW      (2 * 1024 * 1024)
#define SSH_CHANNEL_MAXPKT      32768

#define SSH_MSG_DISCONNECT               1
#define SSH_MSG_IGNORE                   2
#define SSH_MSG_UNIMPLEMENTED            3
#define SSH_MSG_DEBUG                    4
#define SSH_MSG_SERVICE_REQUEST          5
#define SSH_MSG_SERVICE_ACCEPT           6
#define SSH_MSG_KEXINIT                 20
#define SSH_MSG_NEWKEYS                 21
#define SSH_MSG_KEX_ECDH_INIT          30
#define SSH_MSG_KEX_ECDH_REPLY         31
#define SSH_MSG_USERAUTH_REQUEST       50
#define SSH_MSG_USERAUTH_FAILURE       51
#define SSH_MSG_USERAUTH_SUCCESS       52
#define SSH_MSG_USERAUTH_BANNER        53
#define SSH_MSG_GLOBAL_REQUEST         80
#define SSH_MSG_REQUEST_SUCCESS         81
#define SSH_MSG_REQUEST_FAILURE         82
#define SSH_MSG_CHANNEL_OPEN           90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM   91
#define SSH_MSG_CHANNEL_OPEN_FAILURE   92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST  93
#define SSH_MSG_CHANNEL_DATA           94
#define SSH_MSG_CHANNEL_EXTENDED_DATA  95
#define SSH_MSG_CHANNEL_EOF            96
#define SSH_MSG_CHANNEL_CLOSE          97
#define SSH_MSG_CHANNEL_REQUEST        98
#define SSH_MSG_CHANNEL_SUCCESS        99
#define SSH_MSG_CHANNEL_FAILURE       100

#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    1
#define SSH_DISCONNECT_PROTOCOL_ERROR                 2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED            3
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER        13

namespace stardust { class instance; }

namespace starburst {

    struct SshSession {
        uintptr_t sock;
        bool      active;
        bool      encrypted;
        bool      authenticated;
        char      last_error[128];

        uint8_t   session_id[32];
        uint32_t  session_id_len;

        BCRYPT_ALG_HANDLE h_aes;
        BCRYPT_KEY_HANDLE enc_key;
        BCRYPT_KEY_HANDLE dec_key;
        uint8_t   enc_iv[16];
        uint8_t   dec_iv[16];

        uint8_t   mac_key_cs[32];
        uint8_t   mac_key_sc[32];

        uint32_t  seq_cs;
        uint32_t  seq_sc;

        uint32_t  local_channel;
        uint32_t  remote_channel;
        uint32_t  remote_window;
        uint32_t  local_window;
        bool      channel_open;
        bool      channel_eof;
        bool      channel_closed;
        int32_t   exit_status;

        char      host[256];
        char      username[128];
        char      password[256];
        uint8_t*  key_data;
        uint32_t  key_len;
        uint16_t  port;
        uint32_t  id;
    };

    struct SshClientState {
        SshSession sessions[SSH_MAX_SESSIONS];
        HMODULE    h_ws2;
        HMODULE    h_bcrypt;
        BCRYPT_ALG_HANDLE h_sha256_plain;
        bool       initialized;
        bool       wsa_started;
        char       last_error[256];

        // ws2_32 APIs (same as socks WsApis but we keep our own to avoid coupling)
        int   (__stdcall *pWSAStartup)( uint16_t, void* );
        uintptr_t (__stdcall *psocket)( int, int, int );
        int   (__stdcall *pconnect)( uintptr_t, const void*, int );
        int   (__stdcall *psend)( uintptr_t, const char*, int, int );
        int   (__stdcall *precv)( uintptr_t, char*, int, int );
        int   (__stdcall *pclosesocket)( uintptr_t );
        int   (__stdcall *pselect)( int, void*, void*, void*, const void* );
        int   (__stdcall *pioctlsocket)( uintptr_t, long, unsigned long* );
        int   (__stdcall *pgetaddrinfo)( const char*, const char*, const void*, void** );
        void  (__stdcall *pfreeaddrinfo)( void* );
        int   (__stdcall *pWSAGetLastError)( void );
        int   (__stdcall *pWSACleanup)( void );
        uint16_t (__stdcall *phtons)( uint16_t );
        unsigned long (__stdcall *pinet_addr)( const char* );

        // BCrypt ECDH APIs (beyond what's in instance.bcrypt_mod)
        NTSTATUS (__stdcall *pBCryptGenerateKeyPair)( BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, ULONG, ULONG );
        NTSTATUS (__stdcall *pBCryptFinalizeKeyPair)( BCRYPT_KEY_HANDLE, ULONG );
        NTSTATUS (__stdcall *pBCryptExportKey)( BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG );
        NTSTATUS (__stdcall *pBCryptImportKeyPair)( BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG );
        NTSTATUS (__stdcall *pBCryptSecretAgreement)( BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_SECRET_HANDLE*, ULONG );
        NTSTATUS (__stdcall *pBCryptDeriveKey)( BCRYPT_SECRET_HANDLE, LPCWSTR, void*, PUCHAR, ULONG, ULONG*, ULONG );
        NTSTATUS (__stdcall *pBCryptDestroySecret)( BCRYPT_SECRET_HANDLE );
        NTSTATUS (__stdcall *pBCryptDestroyKey)( BCRYPT_KEY_HANDLE );
        NTSTATUS (__stdcall *pBCryptSignHash)( BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG );
        BCRYPT_ALG_HANDLE h_rsa;
    };

    auto declfn ssh_client_init(
        _Inout_ stardust::instance& inst
    ) -> bool;

    auto declfn ssh_client_destroy(
        _Inout_ stardust::instance& inst
    ) -> void;

    auto declfn ssh_connect(
        _Inout_ stardust::instance& inst,
        _In_    const char* host,
        _In_    uint16_t port,
        _In_    const char* username,
        _In_    const char* password,
        _In_opt_ const uint8_t* key_data = nullptr,
        _In_    uint32_t key_len = 0
    ) -> int32_t;  // returns session index or -1

    auto declfn ssh_exec(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx,
        _In_    const char* command,
        _Out_   char** output,
        _Out_   uint32_t* output_len
    ) -> bool;

    auto declfn ssh_disconnect(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx
    ) -> void;

    auto declfn ssh_session_alive(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx
    ) -> bool;

    auto declfn ssh_shell_open(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx
    ) -> bool;

    auto declfn ssh_channel_write(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx,
        _In_    const uint8_t* data,
        _In_    uint32_t data_len
    ) -> bool;

    auto declfn ssh_channel_read_nb(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t session_idx,
        _Out_   uint8_t** out_data,
        _Out_   uint32_t* out_len
    ) -> bool;

    auto declfn ssh_last_error(
        _Inout_ stardust::instance& inst
    ) -> const char*;

}

#endif // INCLUDE_CMD_SSH
#endif // STARBURST_SSH_CLIENT_H
