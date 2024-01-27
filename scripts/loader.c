#include <windows.h>
#include <stdio.h>

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

typedef void ( * ShellcodeMain )();

int main( int argc, char** argv )
{
    PVOID ShellcodeBytes = NULL;
    DWORD ShellcodeSize  = 0;
    DWORD OldProtection  = 0;

    LPVOID  ShellcodeMemory = NULL;

    if ( argc < 2 )
    {
        printf( "[-] %s <shellcode path>\n", argv[ 0 ] );
        return 0;
    }

    ShellcodeBytes  = LoadFileIntoMemory( argv[ 1 ], &ShellcodeSize );
    ShellcodeMemory = VirtualAlloc( NULL, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );

    if ( ! ShellcodeMemory )
    {
        printf("[-] Failed to allocate Virtual Memory\n");
        return 0;
    }

    printf( "[*] Address => %p\n", ShellcodeMemory );

    memcpy( ShellcodeMemory, ShellcodeBytes, ShellcodeSize );

    VirtualProtect( ShellcodeMemory, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );

    puts("[+] Execute shellcode... press enter");
    getchar();

    ((ShellcodeMain)ShellcodeMemory)();
}