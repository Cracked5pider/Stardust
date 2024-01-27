#ifndef STARDUST_LDR_H
#define STARDUST_LDR_H

#include <Common.h>

PVOID LdrModulePeb(
    _In_ ULONG Hash
);

PVOID LdrFunction(
    _In_ PVOID Module,
    _In_ ULONG Function
);

#endif //STARDUST_LDR_H
