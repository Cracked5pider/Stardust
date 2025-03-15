[BITS 64]

DEFAULT REL

EXTERN entry
GLOBAL stardust
GLOBAL RipStart

[SECTION .text$A]
    stardust:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  entry
        mov   rsp, rsi
        pop   rsi
    ret

    RipStart:
        call RipPtr
    ret

    RipPtr:
        mov rax, [rsp]
        sub rax, 0x1b
    ret