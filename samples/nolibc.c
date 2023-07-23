void asm_exit(int code) {
    __asm__ (
        " \
        mov     %[code], %%edi \n\t\
        mov     $60, %%rax \n\t\
        syscall"
        : // no outputs
        : [code] "r" (code)
    );
}

void asm_print(char* msg) {
    int len = 0;
    while(msg[len]) {
        ++len;
    }

    __asm__(
        " \
        mov     $1, %%rdi \n\t\
        mov     %[msg], %%rsi \n\t\
        mov     %[len], %%edx \n\t\
        mov     $1, %%rax \n\t\
        syscall"
        // outputs
        :
        //inputs
        : [msg] "r" (msg), [len] "r" (len)
    );
}

int main() {
    asm_print("Hello from C!\n");
    return 0;
}

void _start() {
    asm_exit(main());
}