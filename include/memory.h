#ifndef STARDUST_MEMORY_H
#define STARDUST_MEMORY_H

#include <windows.h>
#include <stdint.h>

namespace memory {
    inline auto zero(
        _Inout_ void*    memory,
        _In_    uint32_t length
    ) -> void {
        RtlSecureZeroMemory( memory, length );
    }

    inline auto copy(
        _Out_ void*    destination,
        _In_  void*    source,
        _In_  uint32_t length
    ) -> void* {
        for ( size_t i = 0; i < length; i++ ) {
            static_cast<uint8_t*>( destination )[ i ] = static_cast<uint8_t *>( source )[ i ];
        };

        return destination;
    }

    inline auto compare(
        _In_ void*     memory1,
        _In_ void*     memory2,
        _In_ uintptr_t length
    ) -> uint32_t {
        auto a = static_cast<char*>( memory1 );
        auto b = static_cast<char*>( memory2 );

        do {
            if ( *a++ != *b++ ) {
                return ( *--a - *--b );
            };
        } while( --length != 0 );

        return 0;
    }
}

#endif //STARDUST_MEMORY_H
