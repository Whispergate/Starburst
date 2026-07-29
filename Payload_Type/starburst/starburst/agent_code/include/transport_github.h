#ifndef STARBURST_TRANSPORT_GITHUB_H
#define STARBURST_TRANSPORT_GITHUB_H

#include <common.h>

#if defined( GITHUB_TRANSPORT )

namespace starburst {

    auto declfn github_init( instance& inst ) -> bool;
    auto declfn github_send( instance& inst, uint8_t* data, uint32_t len, uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn github_destroy( instance& inst ) -> void;

}

#endif
#endif
