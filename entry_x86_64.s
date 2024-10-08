.globl _start
_start:
    #
    # Call the "main_" C function in main.c with "argc" and "argv".
    #
    # int    argc = *<stack pointer>
    # char** argv =  <stack pointer> + 8
    #
    mov (%rsp),%rdi # The first 2 arguments to main_ are passed over
    mov %rsp,%rsi   # rdi and rsi according to the SysV AMD64 ABI --
    add $8,%rsi     # see https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
    call main_

