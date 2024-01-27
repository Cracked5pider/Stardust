#ifndef STARDUST_MACROS_H
#define STARDUST_MACROS_H

//
// instance related macros
//
#define InstanceOffset()  ( U_PTR( & __Instance_offset ) )
#define InstancePtr()     ( ( PINSTANCE ) C_DEF( C_PTR( U_PTR( StRipStart() ) + InstanceOffset() ) ) )
#define Instance()        ( ( PINSTANCE ) __LocalInstance )
#define STARDUST_INSTANCE PINSTANCE __LocalInstance = InstancePtr();


//
// utils macros
//
#define D_API( x )  __typeof__( x ) * x;
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define ST_GLOBAL   __attribute__( ( section( ".global" ) ) )
#define ST_READONLY __attribute__( ( section( ".rdata" ) ) )

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// memory related macros
//
#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory

/* Clion IDE hacks */
#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

#endif //STARDUST_MACROS_H
