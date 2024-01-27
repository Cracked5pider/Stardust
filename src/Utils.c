#include <Common.h>

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
FUNC ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}