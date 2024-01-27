#ifndef STARDUST_DEFS_H
#define STARDUST_DEFS_H

#include <Common.h>

typedef struct _BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

//
// Hashing defines
//
#define H_MAGIC_KEY       5381
#define H_MAGIC_SEED      5
#define H_MODULE_NTDLL    0x70e61753
#define H_MODULE_KERNEL32 0xadd31df0


#endif //STARDUST_DEFS_H
