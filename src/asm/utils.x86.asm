[BITS 32]

DEFAULT REL

GLOBAL _RipData

[SECTION .text$C]
    _RipData:
        call _RetPtrData
    ret

    _RetPtrData:
        mov	eax, [esp]
        sub	eax, 0x5
    ret