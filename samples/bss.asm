        global _start

        section .text

_start: ; load address of `zero`, for debugging purposes
        lea rax, [rel zero]

        ; then just exit with 0
        xor rdi, rdi
        mov rax, 60
        syscall

        section .bss

zero:   resq 16