#ifndef STARBURST_TRANSPORT_MSTEAMS_H
#define STARBURST_TRANSPORT_MSTEAMS_H

#include <common.h>

#if defined( MSTEAMS_TRANSPORT )

namespace starburst {

    auto declfn msteams_init( instance& inst ) -> bool;
    auto declfn msteams_send( instance& inst, uint8_t* data, uint32_t len, uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn msteams_destroy( instance& inst ) -> void;

}

#endif
#endif
