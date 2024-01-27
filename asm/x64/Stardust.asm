;;
;; Stardust
;;

[BITS 64]

;;
;; tell the compiler to access
;; symbols relative to RIP
;;
DEFAULT REL

;;
;; Import
;;
EXTERN PreMain

;;
;; Export
;;
GLOBAL Start
GLOBAL StRipStart
GLOBAL StRipEnd

;;
;; Main shellcode entrypoint.
;;
[SECTION .text$A]
    ;;
    ;; shellcode entrypoint
    ;; aligns the stack by 16-bytes to avoid any unwanted
    ;; crashes while calling win32 functions and execute
    ;; the true C code entrypoint
    ;;
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  PreMain
        mov   rsp, rsi
        pop   rsi
        ret

    ;;
    ;; get rip to the start of the agent
    ;;
    StRipStart:
        call StRipPtrStart
        ret

    ;;
    ;; get the return address of StRipStart and put it into the rax register
    ;;
    StRipPtrStart:
        mov	rax, [rsp] ;; get the return address
        sub rax, 0x1b  ;; subtract the instructions size to get the base address
        ret            ;; return to StRipStart

;;
;; end of the implant code
;;
[SECTION .text$E]

    ;;
    ;; get end of the implant
    ;;
    StRipEnd:
        call StRetPtrEnd
        ret

    ;;
    ;; get the return address of StRipEnd and put it into the rax register
    ;;
    StRetPtrEnd:
        mov rax, [rsp] ;; get the return address
        add	rax, 0xb   ;; get implant end address
        ret            ;; return to StRipEnd

[SECTION .text$P]

    SymStardustEnd:
        db 'S', 'T', 'A', 'R', 'D', 'U', 'S', 'T', '-', 'E', 'N', 'D'