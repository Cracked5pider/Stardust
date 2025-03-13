#ifndef STARDUST_MACROS_H
#define STARDUST_MACROS_H

#define D_API( x )  decltype( x ) * x;
#define G_SYM( s )  ( uintptr_t )( RipData() - ( ( ( uintptr_t ) &RipData ) - ( ( uintptr_t ) s ) ) )
#define declfn      __attribute__( (section( ".text$B" )) )

#define RESOLVE_IMPORT( m ) { \
    for ( int i = 1; i < expr::struct_count<decltype( instance::m )>(); i++ ) { \
        reinterpret_cast<uintptr_t*>( &m )[ i ] = resolve::_api( m.handle, reinterpret_cast<uintptr_t*>( &m )[ i ] ); \
    } \
}

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

#endif //STARDUST_MACROS_H
