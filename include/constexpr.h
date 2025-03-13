#ifndef STARDUST_CONSTEXPR_H
#define STARDUST_CONSTEXPR_H

#include <stdint.h>

namespace expr {

    template <typename T>
    constexpr size_t struct_count() {
        size_t memberCount  = 0;
        size_t sizeOfStruct = sizeof( T );

        while ( sizeOfStruct > memberCount * sizeof( uintptr_t ) ) {
            memberCount++;
        }

        return memberCount;
    }

    template <typename T = char>
    consteval auto hash_string(
        const T* string
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

#endif //STARDUST_CONSTEXPR_H
