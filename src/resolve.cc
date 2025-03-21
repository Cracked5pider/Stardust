#include <common.h>
#include <native.h>

/*!
 * @brief
 *  searching for the library base address
 *  based on the fvna1 name hash
 *
 * @param library_hash
 *  fnva1 hash of the library name
 *
 * @return
 *  return the base address of the module
 */
auto declfn resolve::module(
   _In_ const uint32_t library_hash
) -> uintptr_t {
    //
    // iterate over the linked list
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !library_hash ) {
            return reinterpret_cast<uintptr_t>( Entry->OriginalBase );
        }

        if ( stardust::hash_string<wchar_t>( Entry->BaseDllName.Buffer ) == library_hash ) {
            return static_cast<uintptr_t>( Entry->OriginalBase );
        }
    } )

    return 0;
}

/*!
 * @brief
 *  resolve function symbol
 *  from specified module
 *
 * @param module_base
 *  module to resolve api from
 *
 * @param symbol_hash
 *  symbol name hash to resolve
 *
 * @return
 *  symbol function pointer
 */
auto declfn resolve::_api(
    _In_ const uintptr_t module_base,
    _In_ const uintptr_t symbol_hash
) -> uintptr_t {
    auto address      = uintptr_t { 0 };
    auto nt_header    = PIMAGE_NT_HEADERS { nullptr };
    auto dos_header   = PIMAGE_DOS_HEADER { nullptr };
    auto export_dir   = PIMAGE_EXPORT_DIRECTORY { nullptr };
    auto export_names = PDWORD { nullptr };
    auto export_addrs = PDWORD { nullptr };
    auto export_ordns = PWORD { nullptr };
    auto symbol_name  = PSTR { nullptr };

    dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>( module_base );
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>( module_base + dos_header->e_lfanew );
    if ( nt_header->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    export_dir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( module_base + nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    export_names = reinterpret_cast<PDWORD>( module_base + export_dir->AddressOfNames );
    export_addrs = reinterpret_cast<PDWORD>( module_base + export_dir->AddressOfFunctions );
    export_ordns = reinterpret_cast<PWORD> ( module_base + export_dir->AddressOfNameOrdinals );

    for ( int i = 0; i < export_dir->NumberOfNames; i++ ) {
        symbol_name = reinterpret_cast<PSTR>( module_base + export_names[ i ] );

        if ( stardust::hash_string( symbol_name ) != symbol_hash ) {
            continue;
        }

        address = module_base + export_addrs[ export_ordns[ i ] ];

        break;
    }

    return address;
}
