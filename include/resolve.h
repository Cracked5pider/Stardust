#ifndef STARDUST_RESOLVE_H
#define STARDUST_RESOLVE_H

#include <windows.h>
#include <stdint.h>
#include <macros.h>

#define RESOLVE_TYPE( s )   .s = reinterpret_cast<decltype(s)*>( expr::hash_string( # s ) )
#define RESOLVE_API( m, s ) resolve::api<decltype(s)>( m, expr::hash_string( # s ) )

namespace resolve {
    auto declfn module(
       _In_ const uint32_t library_hash
    ) -> uintptr_t;

    auto declfn _api(
        _In_ const uintptr_t module_base,
        _In_ const uintptr_t symbol_hash
    ) -> uintptr_t;

    template <typename T>
    inline auto declfn api(
        _In_ const uintptr_t module_base,
        _In_ const uintptr_t symbol_hash
    ) -> T* {
        return reinterpret_cast<T*>( _api( module_base, symbol_hash ) );
    }
}

#endif //STARDUST_RESOLVE_H
