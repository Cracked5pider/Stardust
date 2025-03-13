[BITS 32]

DEFAULT REL

EXTERN _entry
GLOBAL _stardust
GLOBAL _RipStart

[SECTION .text$A]
    _stardust:
        push ebp
        mov  ebp, esp
        call _entry
        mov  esp, ebp
        pop  ebp
    ret

    _RipStart:
        call _RipPtr
    ret

    _RipPtr:
        mov eax, [esp]
        sub eax, 0x11
    ret

[SECTION .text$E]
    SymbolEnd:
        db 'S', 'T', 'A', 'R', 'D', 'U', 'S', 'T', '-', 'E', 'N', 'D'