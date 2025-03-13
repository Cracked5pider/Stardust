#include <common.h>
#include <constexpr.h>
#include <resolve.h>

using namespace stardust;

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

declfn instance::instance(
    void
) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }

    //
    // let the macro handle the resolving part automatically
    //

    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );
}

auto declfn instance::start(
    _In_ void* arg
) -> void {
    const auto user32 = kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );

    if ( user32 ) {
        DBG_PRINTF( "oh wow look we loaded user32.dll -> %p\n", user32 );
    } else {
        DBG_PRINTF( "okay something went wrong. failed to load user32 :/\n", user32 );
    }

    DBG_PRINTF( "running from %ls (Pid: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess );

    DBG_PRINTF( "shellcode @ %p [%d bytes]\n", base.address, base.length );

    decltype( MessageBoxA ) * msgbox = RESOLVE_API( reinterpret_cast<uintptr_t>( user32 ), MessageBoxA );
    decltype( MessageBoxA ) * msgbox = resolve::api<decltype(MessageBoxA)>( reinterpret_cast<uintptr_t>( user32 ), expr::hash_string( "MessageBoxA" ) );

    msgbox( nullptr, symbol<const char*>( "Hello world" ), symbol<const char*>( "caption" ), MB_OK );
}