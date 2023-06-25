global _start

section .text

_start: mov rdi, 1    ; fd = stdout
        mov rsi, msg
        mov rdx, 9    ; 8 chars + newline
        mov rax, 1    ; write syscall
        syscall

        xor rdi, rdi  ; exit with 0
        mov rax, 60   ; exit syscall
        syscall

        section .data

msg:    db "hi there", 10