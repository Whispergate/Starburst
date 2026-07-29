#ifndef STARBURST_TRANSPORT_SMB_H
#define STARBURST_TRANSPORT_SMB_H

#include <common.h>

#if defined( SMB_TRANSPORT )

namespace starburst {

    using namespace stardust;

    auto declfn smb_init( instance& inst ) -> bool;
    auto declfn smb_send( instance& inst, uint8_t* data, uint32_t len, uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn smb_recv( instance& inst, uint8_t** data, uint32_t* len ) -> bool;
    auto declfn smb_destroy( instance& inst ) -> void;

    auto declfn smb_pipe_create( instance& inst ) -> bool;
    auto declfn smb_pipe_send( instance& inst, HANDLE pipe, uint8_t* data, uint32_t len ) -> bool;
    auto declfn smb_pipe_recv( instance& inst, HANDLE pipe, uint8_t** data, uint32_t* len ) -> bool;

}

#endif
#endif
