#define TESTS_FILE "./tests.txt"
#define STDERR_FILENO 2

typedef signed long int   isize;
typedef unsigned long int usize;

typedef unsigned char      u8;
typedef unsigned short int u16;

// TODO: Check architecture!
typedef unsigned int u32;
typedef signed   int i32;

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
    DROP,
    SWAP,
    JUMP_FOREWARD,
    IGNORE_JUMP_IF_STACK_TOP,
    LOAD_PREV_INSTRUCTIONS,
    PRINT,
} Operation;

usize compile_to_instruction_bytecode(char* source, u8* bytecode) {
    // Stores the label and bytecode offset of labeled instructions
    // '<label>\0<offset:u32>'
    u8    labels_byte_offsets[16 * 1024];
    usize labels_byte_offsets_len = 0;

    const usize braces_max_depth = 256;
    // Stores the starting position of the bytecode, generated for a set of
    // instructions in braces:
    //     +----------------+-- positions are stored on the stack --+
    //     v                v                                       v
    //     { <instructions> { <instructions> } <instructions> } ... { ... }
    u32   braces_start_byte_i_stack[braces_max_depth];
    usize braces_start_byte_i_size = 0;

    usize source_i = 0;
    usize byte_i   = 0;

    while (source[source_i] != '\0') {
        switch (source[source_i]) {
            // Ignore whitespace
            case ' ': case '\t': case '\n': case '\r':
                source_i++;
                break;

            // Integer constanst generate push instructions
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': {
                i32 x = 0;
                do {
                    x = x*10 + (source[source_i++] - '0');
                } while (source[source_i] >= '0' && source[source_i] <= '9');

                bytecode[byte_i++] = (u8) PUSH_INT;

                *((i32*) (bytecode + byte_i)) = x;
                byte_i += sizeof(i32);

                // Negative numbers are handled in `case '-'` -- see below.
            }; break;

            // Arithmetic, bitwise and logical operators
            case '+': bytecode[byte_i++] = (u8) ADD_INTS; source_i++; break;
            case '-':
                // Handle negative numbers
                if (source[source_i + 1] >= '0' && source[source_i + 1] <= '9') {
                    source_i++;

                    i32 x = 0;
                    do {
                        x = x*10 + (source[source_i++] - '0');
                    } while (source[source_i] >= '0' && source[source_i] <= '9');

                    bytecode[byte_i++] = (u8) PUSH_INT;

                    *((i32*) (bytecode + byte_i)) = -x;
                    byte_i += sizeof(i32);
                // Handle substraction
                } else {
                    bytecode[byte_i++] = (u8) SUB_INTS;
                    source_i++;
                }
                break;
            case '*': bytecode[byte_i++] = (u8) MUL_INTS     ; source_i++; break;
            case '/': bytecode[byte_i++] = (u8) DIV_INTS     ; source_i++; break;
            case '&': bytecode[byte_i++] = (u8) AND_INTS_BITS; source_i++; break;
            case '|': bytecode[byte_i++] = (u8) OR_INTS_BITS ; source_i++; break;
            case '^': bytecode[byte_i++] = (u8) XOR_INTS     ; source_i++; break;
            case '!': bytecode[byte_i++] = (u8) NOT          ; source_i++; break;

            case '{': {
                if (braces_start_byte_i_size >= 256) {
                    err_msg_begin(); {
                        err_msg_extend(
                            "Too much nesting inside braces: { { ... } }!");
                    }; err_msg_end_and_exit(1);
                }

                //
                // An opening brace generates bytecode to jump forward to the
                // end of the bytecode for the instructions, enclosed in the
                // braces. Because we don't know the length of enclosed
                // bytecode yet we use a placeholder u32, set to 0, for the
                // number of bytes to jump and record the starting position
                // of these placeholder bytes, on a stack, so they can be filled
                // in when the braces are closed with '}'.
                //

                bytecode[byte_i++] = (u8) JUMP_FOREWARD;

                braces_start_byte_i_stack[braces_start_byte_i_size++] = byte_i;

                *((u32*) (bytecode + byte_i)) = 0;
                byte_i += sizeof(u32);

                source_i++;
            }; break;
            case '}': {
                if (braces_start_byte_i_size == 0) {
                    err_msg_begin(); {
                        err_msg_extend("Imbalanced braces: { ... } } !");
                    }; err_msg_end_and_exit(1);
                }

                // Fill in the placeholder for the enclosed bytecode length.
                u32 braces_start_byte_i = braces_start_byte_i_stack[--braces_start_byte_i_size];
                *((u32*) (bytecode + braces_start_byte_i)) = byte_i - braces_start_byte_i;

                source_i++;
            }; break;

            // Stack manipulation
            case 'd': // dup and drop
                if (source[source_i + 1] == 'u' &&
                    source[source_i + 2] == 'p'
                ) {
                    bytecode[byte_i++] = (u8) DUP;
                    source_i += 3;
                    break;
                } else if (
                    source[source_i + 1] == 'r' &&
                    source[source_i + 2] == 'o' &&
                    source[source_i + 3] == 'p'
                ) {
                    bytecode[byte_i++] = (u8) DROP;
                    source_i += 4;
                    break;
                }
                // Fallthrough!
            case 's': // swap
                if (source[source_i + 1] == 'w' &&
                    source[source_i + 2] == 'a' &&
                    source[source_i + 3] == 'p'
                ) {
                    bytecode[byte_i++] = (u8) SWAP;
                    source_i += 4;
                    break;
                }
                // Fallthrough!

            // If
            case 'i':
                if (source[source_i + 1] == 'f') {
                    bytecode[byte_i++] = (u8) IGNORE_JUMP_IF_STACK_TOP;
                    source_i += 2;
                    break;
                }
                // Fallthrough!

            // Print
            case 'p':
                if (source[source_i + 1] == 'r' &&
                    source[source_i + 2] == 'i' &&
                    source[source_i + 3] == 'n' &&
                    source[source_i + 4] == 't'
                ) {
                    bytecode[byte_i++] = (u8) PRINT;
                    source_i += 5;
                    break;
                }
                // Fallthrough!

            default: {
                const usize max_label_len = 255;
                char label[max_label_len + 1];
                usize label_len = 0;
                while ((source[source_i] >= 'a' && source[source_i] <= 'z') ||
                       (source[source_i] >= 'A' && source[source_i] <= 'Z') ||
                       (source[source_i] >= '0' && source[source_i] <= '9') ||
                       (source[source_i] == '_')
                ) {
                    if (label_len >= max_label_len) {
                        label[max_label_len - 1] = '\0';
                        err_msg_begin(); {
                            err_msg_extend("Label '");
                            err_msg_extend(label);
                            err_msg_extend(
                                "...' is longer than the maximum allowed label length!");
                        }; err_msg_end_and_exit(1);
                    }
                    label[label_len++] = source[source_i++];
                }

                // Record bytecode offset of labeled instructions '<label>{'
                if (source[source_i] == '{') {
                    for (usize i = 0; i < label_len; ++i) {
                        labels_byte_offsets[labels_byte_offsets_len++] = label[i];
                    }
                    labels_byte_offsets[labels_byte_offsets_len++]  ='\0';
                    *((u32*) (labels_byte_offsets + labels_byte_offsets_len)) = (u32) byte_i;
                    labels_byte_offsets_len += sizeof(u32);
                // Handle calls to labeled instructions '<label><whitespace>'
                } else if (source[source_i] == ' '  || source[source_i] == '\t' ||
                           source[source_i] == '\n' || source[source_i] == '\r' ||
                           source[source_i] == '\0'
                ) {
                    // Linearly search for a matching label. This is
                    // inefficient for programs with many labels.
                    // TODO: Use a hash map or B-tree instead
                    usize i = 0;
                    usize found_label_match = 0;
                    while (i < labels_byte_offsets_len) {
                        usize j = 0;
                        while (labels_byte_offsets[i] != '\0' && j < label_len
                               && labels_byte_offsets[i++] == label[j++]);
                        i += 1;
                        found_label_match = j == label_len;

                        if (found_label_match) break;

                        i += sizeof(u32);
                    }

                    if (found_label_match) {
                        u32 offset = (u32) labels_byte_offsets[i];
                        offset += 1;
                        u32 enclosed_bytes_len = (u32) bytecode[offset] - sizeof(u32);

                        bytecode[byte_i++] = (u8) LOAD_PREV_INSTRUCTIONS;
                        *((u32*) (bytecode + byte_i)) = offset;
                        byte_i += sizeof(u32);
                    }
                    else {
                        label[label_len] = '\0';
                        err_msg_begin(); {
                            err_msg_extend("No instructions previously labeled '");
                            err_msg_extend(label);
                            err_msg_extend("'!");
                        }; err_msg_end_and_exit(1);
                    }
                } else {
                    label[label_len] = '\0';
                    err_msg_begin(); {
                        err_msg_extend("Label '");
                        err_msg_extend(label);
                        err_msg_extend("' followed by invalid character!");
                    }; err_msg_end_and_exit(1);
                }
            }; break;
        }
    }

    return byte_i;
}

typedef enum {
    STACK_UNDERFLOW,
    STACK_OVERFLOW,
    NO_OPENING_BRACE_AFTER_THEN,
    MAX_RECURSION_DEPTH,
} InterpreterError;

usize interpret_bytecode(u8* bytecode, usize bytecode_len, char* output) {
    InterpreterError err;

    char* output_ptr = output;

    u8* source_bytecode_stop_ptr = bytecode + bytecode_len;
    u8* source_byte_ptr          = bytecode;

    const usize tmp_bytecode_max      = 16 * 1024;
    u8          tmp_bytecode[tmp_bytecode_max];
    u8*         tmp_bytecode_stop_ptr = tmp_bytecode + tmp_bytecode_max;
    u8*         tmp_byte_ptr = tmp_bytecode_stop_ptr;

    const usize stack_max_size = 16 * 1024;
    const usize stack_underflow_padding = 2;
    const usize stack_overflow_padding = 2;
    i32         stack[stack_max_size];
    i32*        stack_start_ptr = stack + stack_underflow_padding;
    i32*        stack_stop_ptr  = stack + stack_max_size - stack_overflow_padding;
    i32*        stack_ptr       = stack_start_ptr - 1;

    usize in_tmp_bytecode = 0;
    u8* byte_ptr          = source_byte_ptr;
    u8* bytecode_stop_ptr = source_bytecode_stop_ptr;
    while (1) {
        while (byte_ptr < bytecode_stop_ptr) {
            switch (*byte_ptr++) {
                case PUSH_INT:
                    *(++stack_ptr) = *((i32*) byte_ptr);
                    byte_ptr += sizeof(i32);
                    goto check_stack_not_empty;
                case ADD_INTS:
                    *(stack_ptr - 1) += *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case SUB_INTS:
                    *(stack_ptr - 1) -= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case MUL_INTS:
                    *(stack_ptr - 1) *= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case DIV_INTS:
                    *(stack_ptr - 1) /= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case AND_INTS_BITS:
                    *(stack_ptr - 1) &= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case OR_INTS_BITS:
                    *(stack_ptr - 1) |= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case XOR_INTS:
                    *(stack_ptr - 1) ^= *stack_ptr;
                    --stack_ptr;
                    goto check_stack_not_empty;
                case NOT:
                    *stack_ptr = !(*stack_ptr);
                    break;
                case DUP:
                    *(stack_ptr + 1) = *stack_ptr;
                    ++stack_ptr;
                    goto check_stack_not_empty;
                case DROP:
                    --stack_ptr;
                    goto check_stack_underflow;
                case SWAP:
                    i32 tmp = *stack_ptr;
                    *stack_ptr       = *(stack_ptr - 1);
                    *(stack_ptr - 1) = tmp;
                    break;
                case JUMP_FOREWARD:
                    byte_ptr += *((u32*) byte_ptr);
                    break;
                case IGNORE_JUMP_IF_STACK_TOP:
                    if (*stack_ptr--) {
                        if (byte_ptr == bytecode_stop_ptr ||
                            *(byte_ptr++) != (u8) JUMP_FOREWARD
                        ) {
                            err = NO_OPENING_BRACE_AFTER_THEN;
                            goto err_handling;
                        }
                        byte_ptr += sizeof(u32);
                    }
                    goto check_stack_underflow;
                case LOAD_PREV_INSTRUCTIONS:
                    u8* src_ptr = bytecode + *((u32*) byte_ptr);
                    byte_ptr += sizeof(u32);
                    u32 src_len   = *((u32*) (src_ptr)) - sizeof(u32);
                    src_ptr += sizeof(u32);

                    if (!in_tmp_bytecode) {
                        source_byte_ptr = byte_ptr;

                        byte_ptr          = tmp_byte_ptr;
                        bytecode_stop_ptr = tmp_bytecode_stop_ptr;

                        in_tmp_bytecode = 1;
                    }

                    byte_ptr -= src_len;
                    if (byte_ptr < tmp_bytecode ||
                        // Handle pointer underflow
                        byte_ptr >= tmp_bytecode_stop_ptr
                    ) {
                        err = MAX_RECURSION_DEPTH;
                        goto err_handling;
                    }
                    for (usize i = 0; i < src_len; ++i) {
                        *(byte_ptr + i) = *(src_ptr + i);
                    }
                    break;
                case PRINT:
                    i32 x = *stack_ptr--;

                    usize is_negative = x < 0;
                    if (x < 0) {
                        x = -x;
                        *output_ptr++ = '-';
                    }

                    // 1. Append digits to output
                    char* digits_swap_lower_ptr = output_ptr;
                    do {
                        *output_ptr++ = (x % 10) + '0';
                        x /= 10;
                    } while (x);
                    char* digits_swap_upper_ptr = output_ptr;
                    // 2. Swap digit order
                    while (digits_swap_lower_ptr < digits_swap_upper_ptr) {
                        char tmp = *digits_swap_lower_ptr;
                        *digits_swap_lower_ptr++ = *(--digits_swap_upper_ptr);
                        *digits_swap_upper_ptr = tmp;
                    }

                    *output_ptr++ = '\n';
                    goto check_stack_underflow;
            }

            continue;

        check_stack_not_empty:
            if (stack_ptr < stack_start_ptr) {
                err = STACK_UNDERFLOW;
                goto err_handling;
            }
            continue;

        check_stack_underflow:
            if (stack_ptr < stack_start_ptr - 1) {
                err = STACK_UNDERFLOW;
                goto err_handling;
            }
            continue;

        check_stack_overflow:
            if (stack_ptr >= stack_stop_ptr) {
                err = STACK_OVERFLOW;
                goto err_handling;
            }
        }

        if (!in_tmp_bytecode) break;

        tmp_byte_ptr = byte_ptr;

        byte_ptr          = source_byte_ptr;
        bytecode_stop_ptr = source_bytecode_stop_ptr;

        in_tmp_bytecode = 0;
    }

    // Output the integers, remaining on the stack
    for (i32* ptr = stack_start_ptr; ptr <= stack_ptr; ++ptr) {
        i32 x = *ptr;

        usize is_negative = x < 0;
        if (x < 0) {
            x = -x;
            *output_ptr++ = '-';
        }

        // 1. Append digits to output
        char* digits_swap_lower_ptr = output_ptr;
        do {
            *output_ptr++ = (x % 10) + '0';
            x /= 10;
        } while (x);
        char* digits_swap_upper_ptr = output_ptr;
        // 2. Swap digit order
        while (digits_swap_lower_ptr < digits_swap_upper_ptr) {
            char tmp = *digits_swap_lower_ptr;
            *digits_swap_lower_ptr++ = *(--digits_swap_upper_ptr);
            *digits_swap_upper_ptr = tmp;
        }

        *output_ptr++ = '\n';
    }

    return output_ptr - output;

err_handling:
    *output_ptr++ = 'E'; *output_ptr++ = 'R'; *output_ptr++ = 'R';
    *output_ptr++ = 'O'; *output_ptr++ = 'R';
    *output_ptr++ = ':'; *output_ptr++ = ' ';

    char* err_msg;
    switch (err) {
        case STACK_UNDERFLOW:
            err_msg = "Stack underflow";
            break;
        case STACK_OVERFLOW:
            err_msg = "Stack overflow";
            break;
        case NO_OPENING_BRACE_AFTER_THEN:
            err_msg = "'then' must be followed by braces: { ... }";
            break;
        case MAX_RECURSION_DEPTH:
            err_msg = "Max recursion depth!";
            break;
    }
    for (usize i = 0; err_msg[i] != '\0'; ++i) {
        *output_ptr++ = err_msg[i];
    }

    return output_ptr - output;
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
        write_(1, "Output:\n", 8);
        write_(1, output, output_len);

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

