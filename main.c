#define TESTS_FILE "./tests.txt"
#define STDERR_FILENO 2

typedef signed long int   isize;
typedef unsigned long int usize;

typedef unsigned char      u8;
typedef unsigned short int u16;

// TODO: Check architecture!
typedef signed int i32;

typedef enum {
    SYSCALL_NO_READ  =  0,
    SYSCALL_NO_WRITE =  1,
    SYSCALL_NO_OPEN  =  2,
    SYSCALL_NO_CLOSE =  3,
    SYSCALL_NO_EXIT  = 60,
} SyscallNo;

isize syscall(SyscallNo syscall_no, usize arg0, usize arg1, usize arg2) {
    isize result;
    asm volatile ("syscall;"
        : "=a" (result)
        : "a" (syscall_no), "D" (arg0), "S" (arg1), "d" (arg2)
        : "rcx", "r11", "memory"  // Setting the correct clobbers is very
                                  // important when compiler optimizations
                                  // are enabled!
    );
    return result;
}

isize read_(unsigned int fd, char* buf, usize max_n) {
    return syscall(SYSCALL_NO_READ, fd, (usize) buf, max_n);
}

isize write_(unsigned int fd, char* buf, usize max_n) {
    return syscall(SYSCALL_NO_WRITE, fd, (usize) buf, max_n);
}

isize open_(char* file_path, int flags, int mode) {
    return syscall(SYSCALL_NO_OPEN, (usize) file_path, flags, mode);
}

isize close_(int fd) {
    return syscall(SYSCALL_NO_CLOSE, fd, 0, 0);
}

void exit_(usize exit_code) {
    syscall(SYSCALL_NO_EXIT, exit_code, 0, 0);
}

usize str_len(char* str) {
    usize len = 0;
    while (str[len] != '\0'); len++;
    return len;
}

usize str_copy_into(char* src, char* dest) {
    usize i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i++];
    }
    return i;
}

char  err_msg[4096];
usize err_msg_len = 0;

void err_msg_begin(void) {
    err_msg_len = str_copy_into("ERROR: ", err_msg);
}

void err_msg_extend(char* str) {
    err_msg_len += str_copy_into(str, err_msg + err_msg_len);
}

void err_msg_end(void) {
    err_msg[++err_msg_len] = '\n';
    write_(1, err_msg, err_msg_len + 1);
    err_msg_len = 0;
}

void err_msg_end_and_exit(usize exit_code) {
    err_msg_end();
    exit_(exit_code);
}

isize read_tests_file_content(char* buf, usize max_n) {
    int tests_fd = open_(TESTS_FILE, 0, 0400);
    if (tests_fd == -1) {
        err_msg_begin(); {
            err_msg_extend("Could not open tests file '");
            err_msg_extend(TESTS_FILE);
            err_msg_extend("'!");
        }; err_msg_end_and_exit(1);
    }

    isize n = read_(tests_fd, buf, max_n);
    if (n < 0) {
        err_msg_begin(); {
            err_msg_extend("Failed to read from file '");
            err_msg_extend(TESTS_FILE);
            err_msg_extend("'!");
        }; err_msg_end_and_exit(1);
    }

    close_(tests_fd);

    return n;
}

typedef enum {
    PUSH_INT,
    ADD_INTS,
    SUB_INTS,
    MUL_INTS,
    DIV_INTS,
    AND_INTS_BITS,
    OR_INTS_BITS,
    XOR_INTS,
    NOT,
    DUP,
    SWAP,
} Operation;

usize compile_to_instruction_bytecode(char* source, u8* bytes) {
    Operation char_to_operation[256];
    char_to_operation['+'] = ADD_INTS;
    char_to_operation['-'] = SUB_INTS;
    char_to_operation['*'] = MUL_INTS;
    char_to_operation['/'] = DIV_INTS;
    char_to_operation['&'] = AND_INTS_BITS;
    char_to_operation['|'] = OR_INTS_BITS;
    char_to_operation['^'] = XOR_INTS;
    char_to_operation['!'] = NOT;

    usize source_i = 0;
    usize byte_i   = 0;

    while (source[source_i] != '\0') {
        switch (source[source_i]) {
            case ' ': case '\t': case '\n':
                source_i++;
                break;
            case '+':
            case '*': case '/':
            case '&': case '|': case '^':
            case '!': {
                bytes[byte_i++] = (u8) char_to_operation[source[source_i++]];
            }; break;
            case '-':
                if (source[source_i + 1] >= '0' && source[source_i + 1] <= '9') {
                    source_i++;

                    i32 x = 0;
                    do {
                        x = x*10 + (source[source_i++] - '0');
                    } while (source[source_i] >= '0' && source[source_i] <= '9');

                    bytes[byte_i++] = (u8) PUSH_INT;

                    *((i32*) (bytes + byte_i)) = -x;
                    byte_i += sizeof(i32);
                } else {
                    bytes[byte_i++] = (u8) char_to_operation[source[source_i++]];
                }
                break;
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': {
                i32 x = 0;
                do {
                    x = x*10 + (source[source_i++] - '0');
                } while (source[source_i] >= '0' && source[source_i] <= '9');

                bytes[byte_i++] = (u8) PUSH_INT;

                *((i32*) (bytes + byte_i)) = x;
                byte_i += sizeof(i32);
            }; break;
            case 'd':
                if (source[source_i + 1] == 'u' &&
                    source[source_i + 2] == 'p'
                ) {
                    bytes[byte_i++] = (u8) DUP;
                    source_i += 3;
                    break;
                }
                // Fallthrough!
            case 's':
                if (source[source_i + 1] == 'w' &&
                    source[source_i + 2] == 'a' &&
                    source[source_i + 3] == 'p'
                ) {
                    bytes[byte_i++] = (u8) SWAP;
                    source_i += 4;
                    break;
                }
                // Fallthrough!
            default:
                err_msg_begin(); {
                    err_msg_extend("Illegal character in program source!");
                }; err_msg_end_and_exit(1);
        }
    }

    return byte_i;
}

usize interpret_bytecode(u8* bytecode, usize bytecode_len, char* output) {
    i32   stack[16 * 1024];
    usize stack_size = 0;

    usize output_i = 0;
    usize byte_i   = 0;
    while (byte_i < bytecode_len) {
        switch (bytecode[byte_i++]) {
            case PUSH_INT:
                *(stack + (stack_size++)) = *((i32*) (bytecode + byte_i));
                byte_i += sizeof(i32);
                break;
            case ADD_INTS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] += stack[stack_size];
                break;
            case SUB_INTS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] -= stack[stack_size];
                break;
            case MUL_INTS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] *= stack[stack_size];
                break;
            case DIV_INTS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] /= stack[stack_size];
                break;
            case AND_INTS_BITS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] &= stack[stack_size];
                break;
            case OR_INTS_BITS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] |= stack[stack_size];
                break;
            case XOR_INTS:
                if (stack_size < 2) goto stack_underflow;
                stack[--stack_size - 1] ^= stack[stack_size];
                break;
            case NOT:
                stack[stack_size - 1] = !stack[stack_size - 1];
                break;
            case DUP:
                stack[stack_size++] = stack[stack_size - 1];
                break;
            case SWAP:
                i32 tmp = stack[stack_size - 1];
                stack[stack_size - 1] = stack[stack_size - 2];
                stack[stack_size - 2] = tmp;
                break;
        }
    }

    // Output the integers, remaining on the stack
    for (usize i = 0; i < stack_size; ++i) {
        i32 x = stack[i];

        usize is_negative = x < 0;
        if (x < 0) {
            x = -x;
            output[output_i++] = '-';
        }

        // 1. Append digits to output
        usize j = output_i;
        do {
            output[output_i++] = (x % 10) + '0';
            x /= 10;
        } while (x);
        usize k = output_i;
        // 2. Reverse digits
        while (j < k) {
            char tmp = output[j];
            output[j++] = output[--k];
            output[k] = tmp;
        }

        output[output_i++] = '\n';
    }

    return output_i;

stack_underflow:
    output_i = str_copy_into("ERROR: Stack underflow!\n", output);

    return output_i;
}

void _start(void) {
    const usize file_content_capacity = 16 * 1024;
    char        file_content[file_content_capacity];
    isize file_content_len = read_tests_file_content(file_content, file_content_capacity);

    usize i = 0;
    while (i < file_content_len) {
        // Parse the test's source
        char test_source[8 * 1024];
        usize test_source_len = 0;
        while (i < file_content_len) {
            if (file_content[i] == '|') {
                do {
                    test_source[test_source_len++] = file_content[++i];
                } while (i < file_content_len && file_content[i] != '\n');
            } else if (file_content[i] == '>') {
                break;
            } else {
                while (i < file_content_len && file_content[i++] != '\n');
            }
        }
        test_source[test_source_len] = '\0';

        // Parse the test's expected output
        char expected_output[8 * 1024];
        usize expected_output_len = 0;
        while (i < file_content_len) {
            if (file_content[i] == '>') {
                i++;
                do {
                    expected_output[expected_output_len++] = file_content[++i];
                } while (i < file_content_len && file_content[i] != '\n');
            } else if (file_content[i] == '|') {
                break;
            } else {
                while (i < file_content_len && file_content[i++] != '\n');
            }
        }

        //write_(1, "Source:\n", 8);
        write_(1, test_source, test_source_len);
        //write_(1, "Expected output:\n", 17);
        //write_(1, expected_output, expected_output_len);

        u8 bytecode[16 * 1024];
        usize bytecode_len = compile_to_instruction_bytecode(test_source, bytecode);
        //write_(1, "Bytecode:\n", 10);
        //write_(1, bytecode, bytecode_len);

        char  output[4096];
        usize output_len = interpret_bytecode(bytecode, bytecode_len, output);
        //write_(1, "Output:\n", 8);
        //write_(1, output, output_len);

        if (output_len != expected_output_len) goto test_failure;
        for (usize j = 0; j < output_len; ++j) {
            if (output[j] != expected_output[j])
                goto test_failure;
        }

        write_(1, "PASS\n", 5);
        continue;

    test_failure:
        err_msg_begin(); {
            err_msg_extend("Test Failed!");
        }; err_msg_end_and_exit(1);
    }

    exit_(0);
}

