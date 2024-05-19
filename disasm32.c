/**
 * @file disas.c
 * @author Joe Bayer (joexbayer)
 * @brief Tiny x86 32bit disassembler
 * @version 0.1
 * @date 2024-05-19
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint8_t opcode;
    const char *mnemonic;
} opcode_t;

typedef struct {
    uint8_t mod;
    uint8_t reg_opcode;
    uint8_t rm;
} modrm_t;

typedef struct {
    uint8_t scale;
    uint8_t index;
    uint8_t base;
} sib_t;

const char *reg_names[8] = {"%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi"};
const char *seg_names[6] = {"es", "cs", "ss", "ds", "fs", "gs"};

typedef enum {
    SEG_ES,
    SEG_CS,
    SEG_SS,
    SEG_DS,
    SEG_FS,
    SEG_GS
} seg_t;

/* Function to decode ModR/M byte */
modrm_t decode_modrm(uint8_t byte) {
    modrm_t modrm;
    modrm.mod = (byte >> 6) & 0x03;
    modrm.reg_opcode = (byte >> 3) & 0x07;
    modrm.rm = byte & 0x07;
    return modrm;
}

/* Function to decode SIB byte */
sib_t decode_sib(uint8_t byte) {
    sib_t sib;
    sib.scale = (byte >> 6) & 0x03;
    sib.index = (byte >> 3) & 0x07;
    sib.base = byte & 0x07;
    return sib;
}

/* Prototypes */
uint8_t fetch_byte(const uint8_t *buffer, size_t *offset);
int disassemble_instruction(const uint8_t *buffer, size_t length, size_t *offset);
modrm_t get_modrm(const uint8_t *buffer, size_t *offset);

static uint32_t segment_override = 0;

uint8_t fetch_byte(const uint8_t *buffer, size_t *offset) {
    uint8_t byte = buffer[(*offset)++];
    printf( "\x1b[31m" "%02x " "\x1b[0m", byte);
    return byte;
}

uint32_t fetch_immediate(const uint8_t *buffer, size_t *offset, size_t size) {
    uint32_t value = 0;
    for (size_t i = 0; i < size; i++) {
        value |= fetch_byte(buffer, offset) << (i * 8);
    }
    return value;
}

modrm_t get_modrm(const uint8_t *buffer, size_t *offset) {
    uint8_t modrm_byte = fetch_byte(buffer, offset);
    return decode_modrm(modrm_byte);
}

int32_t get_displacement(const uint8_t *buffer, size_t *offset, uint8_t mod) {
    int32_t displacement = 0;
    if (mod == 1) {  /* 8-bit displacement */
        displacement = (int8_t)fetch_byte(buffer, offset);  /* Sign-extend the 8-bit displacement */
    } else if (mod == 2) {  /* 32-bit displacement */
        displacement = fetch_immediate(buffer, offset, 4);
    }
    return displacement;
}

int disassemble_instruction(const uint8_t *buffer, size_t length, size_t *offset)
{
    uint8_t opcode;
    modrm_t modrm;
    const char *mnemonic = NULL;
    if(*offset >= length) {
        return -1   ;
    }

    opcode = fetch_byte(buffer, offset);
    switch (opcode){
    case 0xf3: /* endbr32 */
        if(buffer[*offset] == 0x0f && buffer[*offset + 1] == 0x1e && buffer[*offset + 2] == 0xfb){
            for(int i = 0; i < 3; i++){
                fetch_byte(buffer, offset);
            }
            printf("endbr32\n");
        } else {
            printf("TODO: Implement other options for 0xf3\n");
            exit(1);
        }
        break;
    case 0x0f: { /* Extended opcode prefix */
            uint8_t next_byte = fetch_byte(buffer, offset);
            switch (next_byte) {
                case 0xb6: { /* movzbl */
                    modrm_t modrm = get_modrm(buffer, offset);
                    int32_t displacement = get_displacement(buffer, offset, modrm.mod);

                    if (modrm.mod == 3) { /* Register to register */
                        printf("movzbl %s, %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                    } else { /* Memory to register */
                        if (displacement == 0) {
                            printf("movzbl (%s), %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                        } else {
                            printf("movzbl %d(%s), %s\n", displacement, reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                        }
                    }
                }
                break;

                case 0x84: { /* test */
                    modrm_t modrm = get_modrm(buffer, offset);
                    int32_t displacement = get_displacement(buffer, offset, modrm.mod);

                    if (modrm.mod == 3) { /* Register to register */
                        printf("test %s, %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                    } else { /* Memory to register */
                        if (displacement == 0) {
                            printf("test (%s), %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                        } else {
                            printf("test %d(%s), %s\n", displacement, reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
                        }
                    }
                }
                break;

                /* TODO: Add more on extended ops on demand */

                default:
                    printf("Unknown extended opcode 0x0f 0x%02x\n", next_byte);
                    exit(1);
            }
        }
    break;

    case 0x90: /* nop */
        printf("nop\n");
        break;
    case 0x55: /* push %ebp */
        printf("push %%ebp\n");
        break;
    case 0x89: { /* mov */
            modrm_t modrm = get_modrm(buffer, offset);

            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            if (modrm.mod == 3) { /* Register to register */
                printf("mov %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else { /* Register to memory */
                if (displacement == 0) {
                    printf("mov %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("mov %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
            }
        }
        break;

    case 0x83: { /* sub, add, cmp */
        modrm_t modrm = get_modrm(buffer, offset);
        int32_t immediate_value = 0;
        int32_t displacement = get_displacement(buffer, offset, modrm.mod);

        /* Fetch the immediate value (1 byte) */
        immediate_value = (int8_t)fetch_byte(buffer, offset);

        /* Print the disassembled instruction based on the reg_opcode field */
        switch (modrm.reg_opcode) {
            case 5: /* sub */
                printf("sub $0x%x, %d(%s)\n", immediate_value, displacement, reg_names[modrm.rm]);
                break;
            case 0: /* add */
                printf("add $0x%x, %d(%s)\n", immediate_value, displacement, reg_names[modrm.rm]);
                break;
            case 7: /* cmp */
                printf("cmp $0x%x, %d(%s)\n", immediate_value, displacement, reg_names[modrm.rm]);
                break;
            default:
                printf("Unknown 0x83 instruction with reg_opcode %d\n", modrm.reg_opcode);
                exit(1);
        }
    }
    break;
    case 0xe8:{ /* call */
            /* Fetch the 32-bit relative address with potential displacement */
            int32_t displacement = (int32_t)fetch_immediate(buffer, offset, 4);
            int32_t target_address = buffer + *offset + displacement;
            printf("call 0x%zx\n", target_address);
        } 
        break;
    case 0x05: /* add */
        printf("add $0x%x, %%eax\n", fetch_immediate(buffer, offset, 4));
        break;
    case 0xc7: { /* mov */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            /* Fetch the immediate value to be moved */
            int32_t value = fetch_immediate(buffer, offset, 4);

            /* Print the disassembled instruction */
            if (modrm.mod == 0 && modrm.rm == 5) { /* Special case: disp32 */
                printf("movl $0x%x, 0x%x\n", value, displacement);
            } else {
                printf("movl $0x%x, %d(%s)\n", value, displacement, reg_names[modrm.rm]);
            }
        }
        break;
    case 0x8b:{/* mov */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

             /* Print the disassembled instruction */
            if (modrm.mod == 0 && modrm.rm == 5) { /* Special case: disp32 */
                int32_t address = fetch_immediate(buffer, offset, 4);
                printf("mov 0x%x, %s\n", address, reg_names[modrm.reg_opcode]);
            } else {
                printf("mov %d(%s), %s\n", displacement, reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            }
        }
        break;
    case 0xc9: /* leave */
        printf("leave\n");
        break;
    case 0xc3: /* ret */
        printf("ret\n");
        return -1;
    case 0x53: /* push %ebx */
        printf("push %%ebx\n");
        break;
    case 0xeb:{ /* jmp short */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("jmp 0x%x\n", current_offset + value);
        }
        break;
    case 0x7e:{ /* jle */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("jle 0x%x\n", current_offset + value);
        }
        break;
    case 0x8d: { /* lea */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);
            /* Print the disassembled instruction */
            printf("lea %d(%s), %s\n", displacement, reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
        }
        break;
    case 0x52: /* push %edx */
        printf("push %%edx\n");
        break;
    case 0x01: { /* add */
            modrm_t modrm = get_modrm(buffer, offset);
            if (modrm.mod == 3) { /* Register to register */
                printf("add %s, %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            } else { /* Register to memory */
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                if (displacement == 0) {
                    printf("add %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("add %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
            }
        }
    break;
    case 0x84: { /* test */
            modrm_t modrm = get_modrm(buffer, offset);

            if (modrm.mod == 3) { /* Register to register */
                printf("test %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else { /* Memory to register */
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                if (displacement == 0) {
                    printf("test %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("test %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
            }
        }
    break;
    case 0x75:{ /* jne */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("jne 0x%x\n", current_offset + value);
        }
        break;
    case 0x3c: /* cmp */
        printf("cmp $0x%x, %%al\n", fetch_byte(buffer, offset));
        break;
    case 0x81:{ /* Extended immediate arithmetic */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t immediate_value = 0;
            int32_t displacement = 0;
            
            switch (modrm.reg_opcode) {
                case 0: /* add */
                    immediate_value = fetch_immediate(buffer, offset, 4);
                    if (modrm.mod == 3) { /* Register to register */
                        printf("add $0x%x, %s\n", immediate_value, reg_names[modrm.rm]);
                    } else { /* Memory to register */
                        displacement = get_displacement(buffer, offset, modrm.mod);
                        immediate_value = fetch_immediate(buffer, offset, 4);
                        if (displacement == 0) {
                            printf("add $0x%x, (%s)\n", immediate_value, reg_names[modrm.rm]);
                        } else {
                            printf("add $0x%x, %d(%s)\n", immediate_value, displacement, reg_names[modrm.rm]);
                        }
                    }
                    break;
                default:
                    printf("Unknown 0x81 instruction with reg_opcode %d\n", modrm.reg_opcode);
                    exit(1);
                    break;
            }
        }
    break;
    case 0x65: /* gs */
        segment_override = SEG_GS;
        break;
    case 0xa1: { /* mov */
            if(segment_override == SEG_GS) {
                printf("mov %%gs:0x%x, %%eax\n", fetch_immediate(buffer, offset, 4));
                segment_override = 0;
            } else {
                printf("Unsupported segment override or missing segment override for 0xa1 opcode.\n");
                exit(1);
            }
        }
    break;
    case 0x31: { /* xor */
            modrm_t modrm = get_modrm(buffer, offset);
            if (modrm.mod == 3) { /* Register to register */
                printf("xor %s, %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            } else { /* Register to memory */
                printf("Not implemented: xor\n");
                exit(1);
            }
        }
    break;
    case 0xff: { /* inc, dec, call, jmp, push (based on ModR/M byte) */
            modrm_t modrm = get_modrm(buffer, offset);

            if (modrm.reg_opcode == 6) { /* push */
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                if (modrm.mod == 0) {
                    printf("push (%s)\n", reg_names[modrm.rm]);
                } else if (modrm.mod == 1 || modrm.mod == 2) {
                    printf("push %d(%s)\n", displacement, reg_names[modrm.rm]);
                }
            } else {
                printf("Unsupported ff opcode with reg_opcode %d\n", modrm.reg_opcode);
            }
        }
        break;
    case 0x50: /* push %eax */
        printf("push %%eax\n");
        break;
    case 0x3b: { /* cmp */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            if (modrm.mod == 0) {
                printf("cmp (%s), %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            } else if (modrm.mod == 1 || modrm.mod == 2) {
                printf("cmp %d(%s), %s\n", displacement, reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            }
        }
    break;
    case 0x72:{ /* jb */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("jb 0x%x\n", current_offset + value);
        }
        break;
    case 0x6a: /* push */
        printf("push $0x%x\n", (int8_t)fetch_byte(buffer, offset));
        break;
    case 0x39: { /* cmp */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            if (modrm.mod == 0) {
                printf("cmp %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else if (modrm.mod == 1 || modrm.mod == 2) {
                printf("cmp %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
            }
        }
    break;
    case 0x77:{ /* ja */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("ja 0x%x\n", current_offset + value);
        }
        break;
    case 0xb8: { /* mov imm32, eax */
            uint32_t immediate_value = fetch_immediate(buffer, offset, 4);
            printf("mov $0x%x, %%eax\n", immediate_value);
        }
        break;
    case 0x33: { /* xor */
            if (segment_override == SEG_GS) { /* Segment override: gs */
                modrm_t modrm = get_modrm(buffer, offset);
                uint32_t displacement = fetch_immediate(buffer, offset, 4);

                if (modrm.mod == 0 && modrm.rm == 5) { /* 32-bit displacement */
                    printf("xor %%gs:0x%x, %s\n", displacement, reg_names[modrm.reg_opcode]);
                } else {
                    printf("Unsupported addressing mode for 0x33 opcode with segment override.\n");
                }
            } else {
                printf("Unsupported segment override or missing segment override for 0x33 opcode.\n");
                exit(1);
            }
        }
    break;
    case 0x74:{ /* je */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("je 0x%x\n", current_offset + value);
        }
        break;
    default:
        printf("Unknown opcode: %02x\n", opcode);
        exit(1);
        break;
    }

    return 0;
}

static void hexdump(const uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (i % 16 == 0) {
            printf("%08zx: ", i);
        }

        printf("%02x ", buffer[i]);
        if((i+1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

static int32_t func_length(uint8_t *binary_code) {
    int length = 0;
    while(!(*binary_code == 0xc3 && *(binary_code-1) == 0xc9)){
        length++;
        binary_code++;
    }
    return length + 1; // include the ret instruction
}

int test(const char* str) 
{
	int len = 0;
	while (str[len])
		len++;
	return len;
}

int main() {
    int (*func_ptr)() = test;
    uint8_t *binary_code = (uint8_t *)func_ptr;
    size_t length = func_length(binary_code);

    hexdump(binary_code, length);

    printf("Disassembling function at address %p (%d)\n", func_ptr, length);
    size_t offset = 0;
    while (offset < length) {
        disassemble_instruction(binary_code, length, &offset);
    }

    return 0;
}
