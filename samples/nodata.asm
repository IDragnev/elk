global _start

section .text

_start: mov rdi, 1      ; stdout fd
        sub rsp, 10     ; allocate 10 bytes on the stack
        mov byte [rsp+0], 111
        mov byte [rsp+1], 107
        mov byte [rsp+2], 97
        mov byte [rsp+3], 121
        mov byte [rsp+4], 32
        mov byte [rsp+5], 116
        mov byte [rsp+6], 104
        mov byte [rsp+7], 101
        mov byte [rsp+8], 110
        mov byte [rsp+9], 10
        mov rsi, rsp    ; addr 
        mov rdx, 10     ; size
        mov rax, 1      ; write syscall
        syscall
        add rsp, 10     ; free stack memory

        xor rdi, rdi    ; ret = 0
        mov rax, 60     ; exit syscall
        syscall