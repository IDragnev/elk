int asm_strlen(char* s) {
    int len = 0;
    while (s[len] != '\0') {
        ++len;
    }

    return len;
}

void asm_print(char* msg) {
    __asm__ (
        " \
        mov      $1, %%rdi \n\t\
        mov      %[msg], %%rsi \n\t\
        mov      %[len], %%edx \n\t\
        mov      $1, %%rax \n\t\
        syscall"
        // outputs
        : 
        // inputs
        : [msg] "r" (msg), [len] "r" (asm_strlen(msg))
    );
}

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

char* get_msg_root() {
    return "Hello, root!\n";
}

char* get_msg_user() {
    return "Hello, regular user!\n";
}

typedef char* (*get_msg_t)();

static get_msg_t resolve_get_msg() {
    int uid;

     __asm__ (
            " \
            mov     $102, %%rax \n\t\
            syscall \n\t\
            mov     %%eax, %[uid]"
            : [uid] "=r" (uid)
            : // no inputs
    );

    if (uid == 0) {
        return get_msg_root;
    } else {
        return get_msg_user;
    }
}

char* get_msg() __attribute__ ((ifunc ("resolve_get_msg")));

int main() {
    asm_print(get_msg());
    return 0;
}

void _start() {
    asm_exit(main());
}