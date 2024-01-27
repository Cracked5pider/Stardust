#ifndef STARDUST_CONSTEXPR_H
#define STARDUST_CONSTEXPR_H

#include <Common.h>

#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = { 0 };
    CHAR  Char = { 0 };

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        /* turn current character to uppercase */
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

#endif //STARDUST_CONSTEXPR_H
