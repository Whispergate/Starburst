#include <common.h>
#include <module.h>

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
#include <transport_http.h>
#endif

#if defined( GITHUB_TRANSPORT )
#include <transport_github.h>
#endif

#if defined( SMB_TRANSPORT )
#include <transport_smb.h>
#endif

#if defined( TCP_TRANSPORT )
#include <transport_tcp.h>
#endif

using namespace stardust;

namespace starburst {

auto declfn transport_init( instance& inst ) -> bool {
#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    return http_init( inst );
#elif defined( GITHUB_TRANSPORT )
    return github_init( inst );
#elif defined( SMB_TRANSPORT )
    return smb_init( inst );
#elif defined( TCP_TRANSPORT )
    return tcp_init( inst );
#else
    return false;
#endif
}

auto declfn transport_send(
    instance& inst,
    uint8_t*  data,
    uint32_t  len,
    uint8_t** response,
    uint32_t* resp_len
) -> bool {
#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    return http_send( inst, data, len, response, resp_len );
#elif defined( GITHUB_TRANSPORT )
    return github_send( inst, data, len, response, resp_len );
#elif defined( SMB_TRANSPORT )
    return smb_send( inst, data, len, response, resp_len );
#elif defined( TCP_TRANSPORT )
    return tcp_send( inst, data, len, response, resp_len );
#else
    return false;
#endif
}

auto declfn transport_destroy( instance& inst ) -> void {
#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )
    http_destroy( inst );
#elif defined( GITHUB_TRANSPORT )
    github_destroy( inst );
#elif defined( SMB_TRANSPORT )
    smb_destroy( inst );
#elif defined( TCP_TRANSPORT )
    tcp_destroy( inst );
#endif
}

} // namespace starburst
