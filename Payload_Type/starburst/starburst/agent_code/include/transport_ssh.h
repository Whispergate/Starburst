#ifndef TRANSPORT_SSH_H
#define TRANSPORT_SSH_H

#include <common.h>

namespace starburst {

auto declfn ssh_init( instance& inst ) -> bool;
auto declfn ssh_send( instance& inst, uint8_t* data, uint32_t len, uint8_t** response, uint32_t* resp_len ) -> bool;
auto declfn ssh_destroy( instance& inst ) -> void;

} // namespace starburst

#endif // TRANSPORT_SSH_H
