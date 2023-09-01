void asm_exit(int code) {
    __asm__(
        " \
        mov %[code], %%edi \n\
        mov $60, %%rax \n\
        syscall"
        :
        : [code] "r" (code)
    );
}

// from libfoo
extern int number;

// from libbar
extern void change_number(void);

void _start(void) {
    change_number();
    change_number();
    change_number();
    asm_exit(number);
}