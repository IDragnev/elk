        global _start

        section .text

_start: ; load address of `zero`, for debugging purposes
        mov rax, zero

        ; then just exit with 0
        xor rdi, rdi
        mov rax, 60
        syscall

        section .bss

pad:    resq 65536
zero:   resq 16