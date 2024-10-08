#define TESTS_FILE "./tests.txt"
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
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
    SKIP_ENCLOSURE,
    END_ENCLOSURE,
    EXEC_ENCLOSURE_IF_STACK_TOP,
    CALL_ENCLOSURE,
    PRINT,
} Operation;

const isize UNCLOSED_ENCLOSURE = -2;

typedef struct {
    usize rollback_byte_i;
    usize rolback_labels_byte_offsets_len;

    // Stores the label and bytecode offset of labeled instructions
    // '<label>\0<offset:u32>'
    u8    labels_byte_offsets[16 * 1024];
    usize labels_byte_offsets_len;

    usize byte_i;
} source_to_bytecode_compiler__State;

void source_to_bytecode_compiler__init(
    source_to_bytecode_compiler__State* state
) {
    state->labels_byte_offsets_len = 0;
    state->byte_i                  = 0;
}

isize source_to_bytecode_compiler__compile(
    source_to_bytecode_compiler__State* state,
    char* source, u8* bytecode,
    usize repl_mode
) {
    isize err_code = -1;

    state->rolback_labels_byte_offsets_len = state->labels_byte_offsets_len;
    state->rollback_byte_i                 = state->byte_i;

    const usize enclosure_start_stack_max_size = 1024 / sizeof(u32);
    u32         enclosure_start_stack[enclosure_start_stack_max_size];
    usize       enclosure_start_stack_i = 0;

    usize source_i = 0;

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

                bytecode[state->byte_i++] = (u8) PUSH_INT;

                *((i32*) (bytecode + state->byte_i)) = x;
                state->byte_i += sizeof(i32);

                // Negative numbers are handled in `case '-'` -- see below.
            }; break;

            // Arithmetic, bitwise and logical operators
            case '+': bytecode[state->byte_i++] = (u8) ADD_INTS; source_i++; break;
            case '-':
                // Handle negative numbers
                if (source[source_i + 1] >= '0' && source[source_i + 1] <= '9') {
                    source_i++;

                    i32 x = 0;
                    do {
                        x = x*10 + (source[source_i++] - '0');
                    } while (source[source_i] >= '0' && source[source_i] <= '9');

                    bytecode[state->byte_i++] = (u8) PUSH_INT;

                    *((i32*) (bytecode + state->byte_i)) = -x;
                    state->byte_i += sizeof(i32);
                // Handle substraction
                } else {
                    bytecode[state->byte_i++] = (u8) SUB_INTS;
                    source_i++;
                }
                break;
            case '*': bytecode[state->byte_i++] = (u8) MUL_INTS     ; source_i++; break;
            case '/': bytecode[state->byte_i++] = (u8) DIV_INTS     ; source_i++; break;
            case '&': bytecode[state->byte_i++] = (u8) AND_INTS_BITS; source_i++; break;
            case '|': bytecode[state->byte_i++] = (u8) OR_INTS_BITS ; source_i++; break;
            case '^': bytecode[state->byte_i++] = (u8) XOR_INTS     ; source_i++; break;
            case '!': bytecode[state->byte_i++] = (u8) NOT          ; source_i++; break;

            case '{': {
                bytecode[state->byte_i++] = (u8) SKIP_ENCLOSURE;
                // Add a placeholder for the enclosure length
                state->byte_i += sizeof(u32);

                enclosure_start_stack[enclosure_start_stack_i++] = state->byte_i;

                source_i++;
            }; break;
            case '}': {
                if (enclosure_start_stack_i == 0) {
                    err_msg_begin(); {
                        err_msg_extend("Imbalanced braces: { ... } }!");
                    }; err_msg_end();
                    return -1;
                }
                // Fill the enclosure length placeholder
                u32 enclosure_start_byte_i =
                    enclosure_start_stack[--enclosure_start_stack_i];
                u32 enclosure_len = state->byte_i - enclosure_start_byte_i;
                *((u32*) (bytecode + state->byte_i - enclosure_len - sizeof(u32))) =
                    enclosure_len;

                bytecode[state->byte_i++] = (u8) END_ENCLOSURE;

                source_i++;
            }; break;

            // Stack manipulation
            case 'd': // dup and drop
                if (source[source_i + 1] == 'u' &&
                    source[source_i + 2] == 'p'
                ) {
                    bytecode[state->byte_i++] = (u8) DUP;
                    source_i += 3;
                    break;
                } else if (
                    source[source_i + 1] == 'r' &&
                    source[source_i + 2] == 'o' &&
                    source[source_i + 3] == 'p'
                ) {
                    bytecode[state->byte_i++] = (u8) DROP;
                    source_i += 4;
                    break;
                }
                // Fallthrough!
            case 's': // swap
                if (source[source_i + 1] == 'w' &&
                    source[source_i + 2] == 'a' &&
                    source[source_i + 3] == 'p'
                ) {
                    bytecode[state->byte_i++] = (u8) SWAP;
                    source_i += 4;
                    break;
                }
                // Fallthrough!

            // If
            case 'i':
                if (source[source_i + 1] == 'f') {
                    bytecode[state->byte_i++] = (u8) EXEC_ENCLOSURE_IF_STACK_TOP;
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
                    bytecode[state->byte_i++] = (u8) PRINT;
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
                        }; err_msg_end();
                        return -1;
                    }
                    label[label_len++] = source[source_i++];
                }

                u8*    labels_byte_offsets     =  state->labels_byte_offsets;
                usize* labels_byte_offsets_len = &state->labels_byte_offsets_len;

                // Record bytecode offset of labeled instructions '<label>{'
                if (source[source_i] == '{') {
                    for (usize i = 0; i < label_len; ++i) {
                        labels_byte_offsets[
                            (*labels_byte_offsets_len)++] = label[i];
                    }
                    state->labels_byte_offsets[
                        (*labels_byte_offsets_len)++]  ='\0';
                    *((u32*) (labels_byte_offsets + *labels_byte_offsets_len)) =
                        (u32) state->byte_i;
                    *labels_byte_offsets_len += sizeof(u32);
                // Handle calls to labeled instructions '<label><whitespace>'
                } else if (source[source_i] == ' '  || source[source_i] == '}' ||
                           source[source_i] == '\t' || source[source_i] == '\n' ||
                           source[source_i] == '\r' || source[source_i] == '\0'
                ) {
                    // Linearly search for a matching label. This is
                    // inefficient for programs with many labels.
                    // TODO: Use a hash map or B-tree instead
                    usize i = 0;
                    usize found_label_match = 0;
                    while (i < *labels_byte_offsets_len) {
                        usize j = 0;
                        while (labels_byte_offsets[i] != '\0' && j < label_len
                               && labels_byte_offsets[i++] == label[j++]);

                        found_label_match = labels_byte_offsets[i] == '\0' &&
                                            j == label_len;
                        if (found_label_match) {
                            i++;
                            break;
                        }

                        while (labels_byte_offsets[i] != '\0') i++;
                        i++;

                        i += sizeof(u32);
                    }

                    if (found_label_match) {
                        u32 offset = *((u32*) (labels_byte_offsets + i));
                        offset += (u32) (1 + sizeof(u32));

                        bytecode[state->byte_i++] = (u8) CALL_ENCLOSURE;
                        *((u32*) (bytecode + state->byte_i)) = offset;
                        state->byte_i += sizeof(u32);
                    } else {
                        label[label_len] = '\0';
                        err_msg_begin(); {
                            err_msg_extend("No instructions previously labeled '");
                            err_msg_extend(label);
                            err_msg_extend("'!");
                        }; err_msg_end();
                        return -1;
                    }
                } else {
                    label[label_len] = '\0';
                    err_msg_begin(); {
                        err_msg_extend("Label '");
                        err_msg_extend(label);
                        err_msg_extend("' followed by invalid character!");
                    }; err_msg_end();
                    return -1;
                }
            }; break;
        }
    }

    if (enclosure_start_stack_i > 0) {
        if (!repl_mode) {
            err_msg_begin(); {
                err_msg_extend("Unclosed braces: { { ... }!");
            }; err_msg_end();
        }
        return UNCLOSED_ENCLOSURE;
    }

    return state->byte_i;
}

void source_to_bytecode_compiler__rollback(source_to_bytecode_compiler__State* state) {
    state->byte_i                  = state->rollback_byte_i;
    state->labels_byte_offsets_len = state->rolback_labels_byte_offsets_len;
}

typedef enum {
    STACK_UNDERFLOW,
    STACK_OVERFLOW,
    NO_OPENING_BRACE_AFTER_IF,
    MAX_RECURSION_DEPTH,
} InterpreterError;

typedef struct {
    u8** rollback_return_address_stack_ptr;
    i32* rollback_stack_ptr;
    u8*  rollback_byte_ptr;

    u8** return_address_stack_ptr;
    u8** return_address_stack_stop_ptr;

    i32* stack_start_ptr;
    i32* stack_stop_ptr;
    i32* stack_ptr;

    u8* bytecode;
    u8* byte_ptr;
} bytecode_interpreter__State;

void bytecode_interpreter__init(bytecode_interpreter__State* state,
    u8* bytecode,
    void* preallocated_memory, usize preallocated_memory_size
) {
    void* memory_ptr = preallocated_memory;

    const usize return_address_stack_max_size = 4096;
    u8**   return_address_stack          = memory_ptr;
    state->return_address_stack_ptr      = return_address_stack;
    state->return_address_stack_stop_ptr =
        return_address_stack + return_address_stack_max_size;
    memory_ptr += return_address_stack_max_size;

    const usize stack_max_size = 16 * 1024;
    const usize stack_underflow_padding = 2 * sizeof(i32);
    const usize stack_overflow_padding  = 2 * sizeof(i32);
    i32*  stack            = memory_ptr;
    state->stack_start_ptr = stack + stack_underflow_padding;
    state->stack_stop_ptr  = stack + stack_max_size - stack_overflow_padding;
    state->stack_ptr       = state->stack_start_ptr - 1;
    memory_ptr += stack_max_size;

    state->bytecode = bytecode;
    state->byte_ptr = bytecode;

    if ((memory_ptr - preallocated_memory) > preallocated_memory_size) {
        err_msg_begin(); {
            err_msg_extend("Not enough preallocated memory for bytecode "
                           "interpreter!");
        }; err_msg_end_and_exit(1);
    }
}

isize bytecode_interpreter__interpret(bytecode_interpreter__State* state,
    usize bytecode_len, char* output
) {
    InterpreterError err;

    state->rollback_byte_ptr                 = state->byte_ptr;
    state->rollback_stack_ptr                = state->stack_ptr;
    state->rollback_return_address_stack_ptr = state->return_address_stack_ptr;

    char* output_ptr = output;

    u8* bytecode_stop_ptr = state->bytecode + bytecode_len;
    while (state->byte_ptr < bytecode_stop_ptr) {
        switch (*state->byte_ptr++) {
            case PUSH_INT:
                *(++state->stack_ptr) = *((i32*) state->byte_ptr);
                state->byte_ptr += sizeof(i32);
                goto check_stack_not_empty;
            case ADD_INTS:
                *(state->stack_ptr - 1) += *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case SUB_INTS:
                *(state->stack_ptr - 1) -= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case MUL_INTS:
                *(state->stack_ptr - 1) *= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case DIV_INTS:
                *(state->stack_ptr - 1) /= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case AND_INTS_BITS:
                *(state->stack_ptr - 1) &= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case OR_INTS_BITS:
                *(state->stack_ptr - 1) |= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case XOR_INTS:
                *(state->stack_ptr - 1) ^= *state->stack_ptr;
                --state->stack_ptr;
                goto check_stack_not_empty;
            case NOT:
                *state->stack_ptr = !(*state->stack_ptr);
                break;
            case DUP:
                *(state->stack_ptr + 1) = *state->stack_ptr;
                ++state->stack_ptr;
                goto check_stack_not_empty;
            case DROP:
                --state->stack_ptr;
                goto check_stack_underflow;
            case SWAP:
                i32 tmp = *state->stack_ptr;
                *state->stack_ptr       = *(state->stack_ptr - 1);
                *(state->stack_ptr - 1) = tmp;
                break;
            case SKIP_ENCLOSURE:
                state->byte_ptr += 
                    *((u32*) state->byte_ptr)  // enclosure length
                    + sizeof(u32)              // + n bytes storing enclosure length
                    + 1;                       // + 1 "END_ENCLOSURE" byte
                break;
            case END_ENCLOSURE:
                u8* return_address = *(--state->return_address_stack_ptr);
                // When an enclosure is used as the body of an 'if', the
                // enclosure's return address is set to 0 to signal that it
                // it does not return and should be ignored.
                if (return_address) state->byte_ptr = return_address;
                break;
            case EXEC_ENCLOSURE_IF_STACK_TOP:
                if (*state->stack_ptr--) {
                    if (state->byte_ptr == bytecode_stop_ptr ||
                        *(state->byte_ptr++) != (u8) SKIP_ENCLOSURE
                    ) {
                        err = NO_OPENING_BRACE_AFTER_IF;
                        goto err_handling;
                    }
                    state->byte_ptr += sizeof(u32);

                    // 'if's don't return so we set their return address to 0.
                    // This signals the future END_ENCLOSURE step not to
                    // return.
                    *state->return_address_stack_ptr++ = 0;
                    if (state->return_address_stack_ptr ==
                        state->return_address_stack_stop_ptr
                    ) {
                        err = MAX_RECURSION_DEPTH;
                        goto err_handling;
                    }
                }
                goto check_stack_underflow;
            case CALL_ENCLOSURE: {
                u32 call_address = *((u32*) state->byte_ptr);
                state->byte_ptr += sizeof(u32);
                *state->return_address_stack_ptr++ = state->byte_ptr;
                if (state->return_address_stack_ptr ==
                    state->return_address_stack_stop_ptr
                ) {
                    err = MAX_RECURSION_DEPTH;
                    goto err_handling;
                }

                state->byte_ptr = state->bytecode + call_address;
            }; break;
            case PRINT:
                i32 x = *state->stack_ptr--;

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
        if (state->stack_ptr < state->stack_start_ptr) {
            err = STACK_UNDERFLOW;
            goto err_handling;
        }
        continue;

    check_stack_underflow:
        if (state->stack_ptr < state->stack_start_ptr - 1) {
            err = STACK_UNDERFLOW;
            goto err_handling;
        }
        continue;

    check_stack_overflow:
        if (state->stack_ptr >= state->stack_stop_ptr) {
            err = STACK_OVERFLOW;
            goto err_handling;
        }
    }

    // Output the integers, remaining on the stack
    if (state->stack_start_ptr <= state->stack_ptr) {
        char* msg_ptr = "Remaining Stack:";
        for (; *msg_ptr != '\0'; ++msg_ptr) {
            *output_ptr++ = *msg_ptr;
        }

        for (i32* ptr = state->stack_start_ptr; ptr <= state->stack_ptr; ++ptr) {
            *output_ptr++ = ' ';

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
        case NO_OPENING_BRACE_AFTER_IF:
            err_msg = "'if' must be followed by braces: { ... }";
            break;
        case MAX_RECURSION_DEPTH:
            err_msg = "Max recursion depth!";
            break;
    }
    for (usize i = 0; err_msg[i] != '\0'; ++i) {
        *output_ptr++ = err_msg[i];
    }
    *output_ptr++ = '\n';

    // We return the negative length to signal error occurance
    return -((isize) (output_ptr - output));
}

void bytecode_interpreter__rollback(bytecode_interpreter__State* state) {
    state->byte_ptr                 = state->rollback_byte_ptr;
    state->stack_ptr                = state->rollback_stack_ptr;
    state->return_address_stack_ptr = state->rollback_return_address_stack_ptr;
}

void run_repl(void) {
    u8    bytecode[16 * 1024];

    char  input[4096];
    usize input_len    = 0;
    usize indent_depth = 0;

    source_to_bytecode_compiler__State compiler_state;
    source_to_bytecode_compiler__init(&compiler_state);

    const usize interpreter_memory_size = 48 * 1024;
    u8*         interpreter_memory[interpreter_memory_size];
    bytecode_interpreter__State interpreter_state;
    bytecode_interpreter__init(&interpreter_state,
            bytecode,
            interpreter_memory, interpreter_memory_size);

    write_(STDOUT_FILENO, "q/quit to quit.\n", 16);
    while (1) {
        for (usize i = 0; i <= indent_depth; ++i) {
            write_(STDOUT_FILENO, ".   ", 4);
        }

        // Handle multi-line input enclosed in braces: { ...\n... }
        if (indent_depth > 0) {
            int input_advance = read_(STDOUT_FILENO, input + input_len, 4096);
            for (usize i = input_len; i < input_len + input_advance; ++i) {
                switch (input[i]) {
                    case '{': indent_depth++; break;
                    case '}': indent_depth--; break;
                }
            }
            input_len += input_advance;
        } else {
            input_len += read_(STDOUT_FILENO, input + input_len, 4096);
        }

        if (indent_depth == 0) {
            if ((input_len == 2 && input[0] == 'q' && input[1] == '\n') ||
                (input_len == 5 &&
                 input[0] == 'q' && input[1] == 'u' && input[2] == 'i' && input[3] == 't'
                 && input[4] == '\n')
            ) {
                write_(STDOUT_FILENO, "Quitting!\n", 10);
                exit_(0);
            }

            input[input_len] = '\0';

            isize compile_result =
                source_to_bytecode_compiler__compile(
                    &compiler_state,
                    input, bytecode, 1);
            if (compile_result < 0) {
                source_to_bytecode_compiler__rollback(&compiler_state);

                if (compile_result == UNCLOSED_ENCLOSURE) {
                    indent_depth = 1;
                } else {
                    // source_to_bytecode_compiler__compile outputs an error message
                    input_len = 0;
                }
                continue;
            }
            usize bytecode_len = compile_result;
            input_len = 0;

            char  output[4096];
            isize output_len = bytecode_interpreter__interpret(
                &interpreter_state,
                bytecode_len, output);
            if (output_len < 0) {
                source_to_bytecode_compiler__rollback(&compiler_state);
                bytecode_interpreter__rollback       (&interpreter_state);

                output_len = -output_len;
            }
            write_(STDOUT_FILENO, output, output_len);
        }
    }
}

void run_tests_from_test_file(void) {
    const usize file_content_capacity = 16 * 1024;
    char        file_content[file_content_capacity];
    isize file_content_len = read_tests_file_content(file_content, file_content_capacity);

    const usize interpreter_memory_size = 48 * 1024;
    u8*         interpreter_memory[interpreter_memory_size];

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

        source_to_bytecode_compiler__State compiler_state;
        source_to_bytecode_compiler__init(&compiler_state);
        u8 bytecode[16 * 1024];
        isize bytecode_len = source_to_bytecode_compiler__compile(
            &compiler_state,
            test_source, bytecode, 0);
        if (bytecode_len < 0) exit_(1);
        //write_(1, "Bytecode:\n", 10);
        //write_(1, bytecode, bytecode_len);

        char  output[4096];
        bytecode_interpreter__State interpreter_state;
        bytecode_interpreter__init(&interpreter_state,
            bytecode,
            interpreter_memory, interpreter_memory_size);
        usize output_len = bytecode_interpreter__interpret(
            &interpreter_state, bytecode_len, output);
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
}

void main_(int argc, char** argv) {
    usize arg_i = 0;
    char* program = argv[arg_i++];

    char* command = argv[arg_i++];
    switch (command[0]) {
        case 'r':
            if (command[1] == 'e' &&
                command[2] == 'p' &&
                command[3] == 'l' &&
                command[4] == '\0'
            ) {
                run_repl();
                break;
            }
            // Fallthrough!
        case 't':
            if (command[1] == 'e' &&
                command[2] == 's' &&
                command[3] == 't' &&
                command[4] == '\0'
            ) {
                run_tests_from_test_file();
                break;
            }
            // Fallthrough!
        default:
            err_msg_begin(); {
                err_msg_extend("Unknown command '");
                err_msg_extend(command);
                err_msg_extend("'!");
            }; err_msg_end();
    }

    exit_(0);
}
