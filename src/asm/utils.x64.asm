[BITS 64]

DEFAULT REL

GLOBAL RipData

[SECTION .text$C]
    RipData:
        call RetPtrData
    ret

    RetPtrData:
        mov	rax, [rsp]
        sub	rax, 0x5
    ret