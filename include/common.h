#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system related headers
#include <windows.h>
#include <type_traits>
#include <concepts>

//
// stardust related headers
#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>

extern "C" auto RipData() -> uintptr_t;
extern "C" auto RipStart() -> uintptr_t;

#if defined( DEBUG )
#define DBG_PRINTF( format, ... ) { ntdll.DbgPrint( symbol<PCH>( "[DEBUG::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, __VA_ARGS__ ); }
#else
#define DBG_PRINTF( format, ... ) { ; }
#endif

#ifdef _M_X64
#define END_OFFSET 0x10
#else
#define END_OFFSET 0x10
#endif

namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(RipData()) - (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s));
    }

    class instance {
        struct {
            uintptr_t address;
            uintptr_t length;
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( GetProcAddress )
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( GetProcAddress )
        };

        struct {
            uintptr_t handle;

            struct
            {
#ifdef DEBUG
                D_API( DbgPrint )
#endif
            };
        } ntdll = {
#ifdef DEBUG
            RESOLVE_TYPE( DbgPrint )
#endif
        };

    public:
        explicit instance();

        auto start(
            _In_ void* arg
        ) -> void;
    };

    template<typename T = char>
    inline auto declfn hash_string(
        _In_ const T* string
    ) -> uint32_t {
        uint32_t hash = 0x811c9dc5;
        uint8_t  byte = 0;

        while ( * string ) {
            byte = static_cast<uint8_t>( * string++ );

            if ( byte >= 'a' ) {
                byte -= 0x20;
            }

            hash ^= byte;
            hash *= 0x01000193;
        }

        return hash;
    }
}


#endif //STARDUST_COMMON_H
