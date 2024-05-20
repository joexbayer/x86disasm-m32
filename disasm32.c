/**
 * @file disasm32.c
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
const char *reg8_names[8] = {"%al", "%cl", "%dl", "%bl", "%ah", "%ch", "%dh", "%bh"};
const char *reg16_names[8] = {"%ax", "%cx", "%dx", "%bx", "%sp", "%bp", "%si", "%di"};

const char *seg_names[6] = {"es", "cs", "ss", "ds", "fs", "gs"};
const char *scale_str[4] = {"", "2", "4", "8"};

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
static uint32_t operand_size_override  = 0;

uint8_t fetch_byte(const uint8_t *buffer, size_t *offset) {
    uint8_t byte = buffer[(*offset)++];
    printf( "\x1b[31m" "%02x " "\x1b[0m", byte);
    return byte;
}

uint32_t fetch_immediate(const uint8_t *buffer, size_t *offset, size_t size) {
    uint32_t value = 0;
    size_t actual_size = operand_size_override ? 2 : size;  // Use 2 bytes if operand size override is set
    for (size_t i = 0; i < actual_size; i++) {
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
        displacement = (int8_t)fetch_byte(buffer, offset);  /* Sign-extend the 8-bit displacement, else dont get the negativ numbers */
    } else if (mod == 2) {  /* 32-bit displacement */
        displacement = fetch_immediate(buffer, offset, 4);
    }
    return displacement;
}

char* sizemod(){
    return operand_size_override ? "w" : "l";
}

void modrm_instruction(const char* instruction, modrm_t modrm, const uint8_t *buffer, size_t *offset, int32_t displacement){
    if (modrm.mod == 3) { 
        printf("%s %s\n", instruction, reg_names[modrm.rm]);
    } else { 
        if (modrm.rm == 4 && modrm.mod != 3) { 
            sib_t sib = decode_sib(fetch_byte(buffer, offset));;
            if (sib.index == 4) {
                printf("%s %d(,%s*%s)\n", instruction, displacement, reg_names[sib.base], scale_str[sib.scale]);
            } else {
                printf("%s %d(%s,%s*%s)\n",instruction, displacement, reg_names[sib.base], reg_names[sib.index], scale_str[sib.scale]);
            }
        } else {
            if (modrm.mod == 0 && modrm.rm == 5) {
                displacement = fetch_immediate(buffer, offset, 4);
                printf("%s 0x%x\n", instruction, displacement);
            } else {
                printf("%s %d(%s)\n", instruction, displacement, reg_names[modrm.rm]);
            }
        }
    }
}

static const char* _x81_mnemonics[] = {
    "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
};
static void _x81(int8_t mnem, const uint8_t *buffer, size_t *offset, modrm_t modrm) {
    int32_t immediate_value = fetch_immediate(buffer, offset, 4);
    int32_t displacement = 0;
    const char *mnemonic = _x81_mnemonics[mnem];

    if (modrm.mod == 3) {
        printf("%s $0x%x, %s\n", mnemonic, immediate_value, reg_names[modrm.rm]);
    } else {
        displacement = get_displacement(buffer, offset, modrm.mod);
        if (displacement == 0) {
            printf("%s $0x%x, (%s)\n", mnemonic, immediate_value, reg_names[modrm.rm]);
        } else {
            printf("%s $0x%x, %d(%s)\n", mnemonic, immediate_value, displacement, reg_names[modrm.rm]);
        }
    }
}

static const char* _xd1_xc1_mnemonics[] = {
    "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"
};
static void _xd1(int8_t mnem, const uint8_t *buffer, size_t *offset, modrm_t modrm, const char* regs[]) {
    int32_t displacement = 0;
    const char *mnemonic = _xd1_xc1_mnemonics[mnem];

    if (modrm.mod == 3) {
        printf("%s %s, 1\n", mnemonic, regs[modrm.rm]);
    } else {
        displacement = get_displacement(buffer, offset, modrm.mod);
        printf("%s %d(%s), 1\n", mnemonic, displacement, regs[modrm.rm]);
    }
}

static void _xd3(int8_t mnem, const uint8_t *buffer, size_t *offset, modrm_t modrm, const char* regs[]) {
    int32_t displacement = 0;
    const char *mnemonic = _xd1_xc1_mnemonics[mnem];

    if (modrm.mod == 3) {
        printf("%s %s, cl\n", mnemonic, regs[modrm.rm]);
    } else {
        displacement = get_displacement(buffer, offset, modrm.mod);
        printf("%s %d(%s), cl\n", mnemonic, displacement, regs[modrm.rm]);
    }
}

static void _xc1(int8_t mnem, const uint8_t *buffer, size_t *offset, uint8_t count, modrm_t modrm){
    int32_t displacement = 0;
    const char *mnemonic = _xd1_xc1_mnemonics[mnem];

   if (modrm.mod == 3) {
        printf("rol %s, $%d\n", reg_names[modrm.rm], count);
    } else {
        printf("rol %d(%s), $%d\n", displacement, reg_names[modrm.rm], count);
    }
}

static const char* _xff_mnemonics[] = {
    "inc", "dec", "call", "lcall", "jmp", "ljmp", "push"
};

static void _xff(int8_t mnem, const uint8_t *buffer, size_t *offset, modrm_t modrm) {
    int32_t displacement = 0;
    const char *mnemonic = _xff_mnemonics[mnem];
    if (modrm.mod == 3) {
        printf("%s %s\n", mnemonic, reg_names[modrm.rm]);
    } else {
        displacement = get_displacement(buffer, offset, modrm.mod);
        printf("%s %d(%s)\n", mnemonic, displacement, reg_names[modrm.rm]);
    }
}

static const char* _xd8_mnemonics[] = {
    "fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"
};

static void _xd8(int8_t mnem, const uint8_t *buffer, size_t *offset, modrm_t modrm) {
    int32_t displacement = 0;
    const char *mnemonic = _xd8_mnemonics[mnem];

    if (modrm.mod == 3) {
        printf("%s %s\n", mnemonic, reg_names[modrm.rm]);
    } else {
        displacement = get_displacement(buffer, offset, modrm.mod);
        printf("%s %d(%s)\n", mnemonic, displacement, reg_names[modrm.rm]);
    }
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
                case 0x84: { /* je rel32 */
                    int32_t displacement = fetch_immediate(buffer, offset, 4);
                    printf("je 0x%x\n", *offset + displacement);
                }
                break;
                case 0x85: { /* jne rel32 */
                    int32_t displacement = fetch_immediate(buffer, offset, 4);
                    printf("jne 0x%x\n", *offset + displacement);
                }
                break;
                case 0x8F: { /* jng/jle rel32 */
                    int32_t displacement = fetch_immediate(buffer, offset, 4);
                    printf("jng 0x%x\n", *offset + displacement);
                }
                break;
                case 0x87: { /* ja rel32 */
                    int32_t displacement = fetch_immediate(buffer, offset, 4);
                    printf("ja 0x%x\n", *offset + displacement);
                }
                break;
                case 0xB6: { /* movzx r16/r32, r/m8 */
                    modrm_t modrm = get_modrm(buffer, offset);

                    if (modrm.mod == 3) { 
                        printf("movzx %s, %s\n", reg_names[modrm.reg_opcode], reg8_names[modrm.rm]);
                    } else { /* Memory to Register */
                        int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                        printf("movzx %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                    }
                }
                break;
                case 0xBE: { /* movsx r32, r/m8 */
                        modrm_t modrm = get_modrm(buffer, offset);
                        if (modrm.mod == 3) {
                            printf("movsx %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                        } else {
                            int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                            if (displacement == 0) {
                                printf("movsx %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                            } else {
                                printf("movsx %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                            }
                        }
                    }
                break;
                case 0xAF: { /* imul */
                    modrm_t modrm = get_modrm(buffer, offset);
                    int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                    modrm_instruction("imul", modrm, buffer, offset, displacement);
                }
                break;
                case 0xB7: { /* movzx r32, r/m16 */
                    modrm_t modrm = get_modrm(buffer, offset);

                    if (modrm.mod == 3) { 
                        printf("movzx %s, %s\n", reg_names[modrm.reg_opcode], reg16_names[modrm.rm]);
                    } else { /* Memory to Register */
                        int32_t displacement = 0;
                        if (modrm.rm == 4) {
                            sib_t sib =  decode_sib(fetch_byte(buffer, offset));
                            if (modrm.mod == 0 && sib.base == 5) {
                                displacement = fetch_immediate(buffer, offset, 4); /* 32-bit displacement */
                                printf("movzx %s, %x(,%s,%d)\n", reg_names[modrm.reg_opcode], displacement, reg_names[sib.index], 1 << sib.scale);
                            } else {
                                if (modrm.mod == 1) displacement = fetch_byte(buffer, offset); /* 8-bit displacement */
                                if (modrm.mod == 2) displacement = fetch_immediate(buffer, offset, 4); /* 32-bit displacement */
                                printf("movzx %s, %d(%s,%s,%d)\n", reg_names[modrm.reg_opcode], displacement, reg_names[sib.base], reg_names[sib.index], 1 << sib.scale);
                            }
                        } else {
                            displacement = get_displacement(buffer, offset, modrm.mod);
                            printf("movzx %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                        }
                    }
                }
                break;
                default:
                    printf("Unknown extended opcode 0x0F 0x%02x\n", next_byte);
                    exit(1);
            }
        }
        break;
    case 0x2D: { /* sub eax, imm32 */
            uint32_t immediate = fetch_immediate(buffer, offset, 4);
            printf("sub $0x%x, %%eax\n", immediate);
        }
        break;
    case 0x0B: { /* or */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            modrm_instruction("or", modrm, buffer, offset, displacement);
        }
        break;
    case 0x99: /* cdq */
        printf("cdq\n");
        break;
    case 0x98: { /* cbw/cwde */
        if (operand_size_override) {    
            printf("cbw\n");
        } else {
            printf("cwde\n");
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

            /* 4 indicates that SIB byte is present */
            if (modrm.rm == 4 && modrm.mod != 3) {
                sib_t sib = decode_sib(fetch_byte(buffer, offset));
                if (sib.index == 4) {
                    printf("mov%s %s, %d(,%s*%s)\n", sizemod(), reg_names[modrm.reg_opcode], displacement, reg_names[sib.base], scale_str[sib.scale]);
                } else {
                    printf("mov%s %s, %d(%s,%s*%s)\n", sizemod(), reg_names[modrm.reg_opcode], displacement, reg_names[sib.base], reg_names[sib.index], scale_str[sib.scale]);
                }
            } else {
                if (modrm.mod == 3) { 
                        printf("mov%s %s, %s\n", sizemod(), reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else { 
                    if (displacement == 0) {
                        printf("mov%s %s, (%s)\n", sizemod(), reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                    } else {
                        printf("mov%s %s, %d(%s)\n", sizemod(),  reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                    }
                }
            }
            operand_size_override  = 0;
        }
        break;

    case 0x83: { /* sub, add, cmp */
        modrm_t modrm = get_modrm(buffer, offset);
        int32_t displacement = get_displacement(buffer, offset, modrm.mod);
        int32_t immediate_value = (int8_t)fetch_byte(buffer, offset);
        switch (modrm.reg_opcode) {
            case 5: /* sub */
                printf("sub%s $0x%x, %d(%s)\n", sizemod(), immediate_value, displacement, reg_names[modrm.rm]);
                break;
            case 0: /* add */
                printf("add%s $0x%x, %d(%s)\n", sizemod(), immediate_value, displacement, reg_names[modrm.rm]);
                break;
            case 7: /* cmp */
                printf("cmp%s $0x%x, %d(%s)\n", sizemod(), immediate_value, displacement, reg_names[modrm.rm]);
                break;
            case 4: /* and */
                printf("and%s $0x%x, %d(%s)\n", sizemod(), immediate_value, displacement, reg_names[modrm.rm]);
                break;
            default:
                printf("Unknown 0x83 instruction with reg_opcode %d\n", modrm.reg_opcode);
                exit(1);
        }
        operand_size_override  = 0;
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
        printf("add%s $0x%x, %%eax\n", sizemod(), fetch_immediate(buffer, offset, 4));
        operand_size_override  = 0;
        break;
    case 0xc7: { /* mov */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);
            int32_t value;

            if(operand_size_override )
                value = (int16_t)fetch_immediate(buffer, offset, 2);
            else
                value = fetch_immediate(buffer, offset, 4);

            if (modrm.mod == 0 && modrm.rm == 5) {
                printf("mov%s $0x%x, 0x%x\n", sizemod(),  value, displacement);
            } else {
                printf("mov%s $0x%x, %d(%s)\n", sizemod(), value, displacement, reg_names[modrm.rm]);
            }
            operand_size_override  = 0;
        }
        break;
    case 0xc1:{
            modrm_t modrm = get_modrm(buffer, offset);
            uint8_t count = fetch_byte(buffer, offset);
            _xc1(modrm.reg_opcode, buffer, offset, count, modrm);
        }
    break;
    case 0x8b: { /* mov r32, r/m32 */
            modrm_t modrm = get_modrm(buffer, offset);
            if (modrm.mod == 3) { 
                printf("mov %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else { /* Memory to Register */
                int32_t displacement = 0;
                if (modrm.rm == 4) {
                    sib_t sib = decode_sib(fetch_byte(buffer, offset));
                    if (modrm.mod == 0 && sib.base == 5) {
                        displacement = fetch_immediate(buffer, offset, 4); /* 32-bit displacement */
                        printf("mov %s, 0x%x(,%s,%d)\n", reg_names[modrm.reg_opcode], displacement, reg_names[sib.index], 1 << sib.scale);
                    } else {
                        displacement = get_displacement(buffer, offset, modrm.mod);
                        printf("mov %s, %d(%s,%s,%d)\n", reg_names[modrm.reg_opcode], displacement, reg_names[sib.base], reg_names[sib.index], 1 << sib.scale);
                    }
                } else {
                    displacement = get_displacement(buffer, offset, modrm.mod);
                    if (segment_override) {
                        printf("mov %s, %d(%%%s:%s)\n", reg_names[modrm.reg_opcode], displacement, seg_names[segment_override], reg_names[modrm.rm]);
                    } else {
                        printf("mov %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                    }
                }
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

            modrm_instruction("lea", modrm, buffer, offset, displacement);
        }
    break;
    case 0x52: /* push %edx */
        printf("push %%edx\n");
        break;
    case 0x01: { /* add */
            modrm_t modrm = get_modrm(buffer, offset);
            if (modrm.mod == 3) { 
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
    case 0xd8: { /* fpu instructions */
            modrm_t modrm = get_modrm(buffer, offset);
            _xd8(modrm.reg_opcode, buffer, offset, modrm);
        }
        break;
    case 0x84: { /* test */
            modrm_t modrm = get_modrm(buffer, offset);

            if (modrm.mod == 3) { 
                printf("test %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else { 
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                if (displacement == 0) {
                    printf("test %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("test %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
            }
        }
    break;
    case 0xE0: { /* loopne */
            int8_t displacement = fetch_byte(buffer, offset);
            int32_t current_offset = (int32_t)&buffer[*offset];
            printf("loopne 0x%x\n", current_offset + displacement);
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
    case 0x81: { /* Extended immediate arithmetic */
            modrm_t modrm = get_modrm(buffer, offset);
            _x81(modrm.reg_opcode, buffer, offset, modrm);
        }
    break;
    case 0x65: /* gs */
        segment_override = SEG_GS;
        return 0;
    case 0x3E: /* DS segment override prefix */
        segment_override = SEG_DS;
        return 0;
    case 0x2e: /* CS segment override prefix */
        segment_override = SEG_CS;
        return 0;
    case 0x26: /* ES segment override prefix */
        segment_override = SEG_ES;
        return 0;
    case 0x64: /* FS segment override prefix */
        segment_override = SEG_FS;
        return 0;
    case 0x36: /* SS segment override prefix */
        segment_override = SEG_SS;
        return 0;
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
            if (modrm.mod == 3) { 
                printf("xor %s, %s\n", reg_names[modrm.rm], reg_names[modrm.reg_opcode]);
            } else {
                printf("Not implemented: xor\n");
                exit(1);
            }
        }
    break;
    case 0xFF: { /* Various instructions */
            modrm_t modrm = get_modrm(buffer, offset);
            _xff(modrm.reg_opcode, buffer, offset, modrm);
        }
        break;
    case 0x23: { /* and */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            modrm_instruction("and", modrm, buffer, offset, displacement);
        }
    break;
    case 0xf7: { /* Handles multiple instructions based on modRM */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            switch (modrm.reg_opcode) {
                case 0: { /* test */
                    uint32_t immediate_value = fetch_immediate(buffer, offset, operand_size_override ? 2 : 4);
                    if (modrm.mod == 3) {
                        printf("test %s, $0x%x\n", reg_names[modrm.rm], immediate_value);
                    } else {
                        if (displacement == 0) {
                            printf("test (%s), $0x%x\n", reg_names[modrm.rm], immediate_value);
                        } else {
                            printf("test %d(%s), $0x%x\n", displacement, reg_names[modrm.rm], immediate_value);
                        }
                    }
                }
                break;
                case 2: /* not */
                    if (modrm.mod == 3) {
                        printf("not %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("not %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                case 3: /* neg */
                    if (modrm.mod == 3) {
                        printf("neg %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("neg %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                case 4: /* mul */
                    if (modrm.mod == 3) {
                        printf("mul %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("mul %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                case 5: /* imul */
                    if (modrm.mod == 3) {
                        printf("imul %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("imul %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                case 6: /* div */
                    if (modrm.mod == 3) {
                        printf("div %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("div %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                case 7: /* idiv */
                    if (modrm.mod == 3) {
                        printf("idiv %s\n", reg_names[modrm.rm]);
                    } else {
                        printf("idiv %d(%s)\n", displacement, reg_names[modrm.rm]);
                    }
                    break;
                default:
                    printf("Unknown F7 instruction with reg_opcode %d\n", modrm.reg_opcode);
                    exit(1);
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

            if (modrm.mod == 3) { 
                printf("cmp %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else { /* Register to Memory */
                if (displacement == 0) {
                    printf("cmp %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("cmp %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
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
                modrm_t modrm = get_modrm(buffer, offset);
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);

                modrm_instruction("xor", modrm, buffer, offset, displacement);
            }
        }
    break;
    case 0x45: { /* inc */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            modrm_instruction("inc", modrm, buffer, offset, displacement);
        }
    break;
    case 0xd1: { /* Various shift and rotate instructions */
            modrm_t modrm = get_modrm(buffer, offset);
            _xd1(modrm.reg_opcode, buffer, offset, modrm, operand_size_override ? reg16_names : reg_names);
        }
        break;
    case 0xd3: { /* Various shift and rotate instructions */
            modrm_t modrm = get_modrm(buffer, offset);
            _xd3(modrm.reg_opcode, buffer, offset, modrm, operand_size_override ? reg16_names : reg_names);
        }
        break;
    case 0xd0: { /* Various shift and rotate instructions */
            modrm_t modrm = get_modrm(buffer, offset);
            _xd1(modrm.reg_opcode, buffer, offset, modrm, reg8_names);
        }
        break;
    case 0x74:{ /* je */
            int32_t current_offset = (int32_t)&buffer[*offset];
            int32_t value = (int8_t)fetch_byte(buffer, offset);
            printf("je 0x%x\n", current_offset + value);
        }
        break;
    case 0x66: /* operand size override */
        operand_size_override  = 1;
        return 0;
    case 0x85: { /* test */
            modrm_t modrm = get_modrm(buffer, offset);
            if (modrm.mod == 3) { 
                printf("test %s, %s\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
            } else {
                int32_t displacement = get_displacement(buffer, offset, modrm.mod);
                if (displacement == 0) {
                    printf("test %s, (%s)\n", reg_names[modrm.reg_opcode], reg_names[modrm.rm]);
                } else {
                    printf("test %s, %d(%s)\n", reg_names[modrm.reg_opcode], displacement, reg_names[modrm.rm]);
                }
            }
        }
    break;
    case 0xBA: { /* mov immediate to edx */
            int32_t immediate_value = fetch_immediate(buffer, offset, 4);
            printf("mov $0x%x, %%edx\n", immediate_value);
        }
    break;
    case 0x58: /* pop %eax */
        printf("pop %%eax\n");
        break;
    case 0x5d: /* pop %ebp */
        printf("pop %%ebp\n");
        break;
    case 0x5b: /* pop %ebx */
        printf("pop %%ebx\n");
        break; 
    case 0x5a: /* pop %edx */
        printf("pop %%edx\n");
        break;
    case 0x5e: /* pop %esi */
        printf("pop %%esi\n");
        break;
    case 0x5f: /* pop %edi */
        printf("pop %%edi\n");
        break;
    case 0x2B: { /* sub */
            modrm_t modrm = get_modrm(buffer, offset);
            int32_t displacement = get_displacement(buffer, offset, modrm.mod);

            modrm_instruction("sub", modrm, buffer, offset, displacement);
        }
    break;
    case 0xec: /* in al, dx */
        printf("in al, dx\n");
        break;
    case 0x57: /* push edi */
        printf("push %%edi\n");
        break;
    case 0x56: /* push esi */
        printf("push %%esi\n");
        break;
    case 0x51: {
            printf("push %%ecx\n");
        }
        break;
    case 0xE9: { /* jmp */
        int32_t displacement = fetch_immediate(buffer, offset, 4);
        int32_t current_offset = (int32_t)&buffer[*offset];

        printf("jmp 0x%x\n", current_offset + displacement);
    }
    break;
    case 0x88: { /* mov r/m8, r8 */
        modrm_t modrm = get_modrm(buffer, offset);
        int32_t displacement = get_displacement(buffer, offset, modrm.mod);

        modrm_instruction("mov", modrm, buffer, offset, displacement);
        }
    break;
    case 0x3d: { /* cmp eax, imm32 */
            uint32_t immediate_value = fetch_immediate(buffer, offset, 4);
            printf("cmp $0x%x, %%eax\n", immediate_value);
        }
        break;
    default:
        printf("Unknown opcode: %02x\n", opcode);
        exit(1);
        break;
    }

    segment_override = 0;
    operand_size_override  = 0;
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

int test() {
    // Variable declarations
    int a = 5;
    int b = 3;
    int c = 0;
    int d = 1;
    int e = 2;
    int f = 4;
    char *str = "Test String";
    int arr[3] = {10, 20, 30};

    // Simple arithmetic operations
    c = a + b;
    d = a - b;
    e = a * b;
    f = a / b;

    // Logical operations
    c = a & b;
    d = a | b;
    e = a ^ b;
    f = ~a;

    // Shift operations
    c = a << 1;
    d = a >> 1;

    // Conditional operations
    if (a == b) {
        c = a + 1;
    } else {
        d = b + 1;
    }

    // Loops
    for (int i = 0; i < 3; i++) {
        c += arr[i];
    }

    // Function call
    printf("Hello, World!\n");

    // Array access
    d = arr[1];

    // Pointer arithmetic
    char *p = str;
    while (*p) {
        p++;
    }
}


int main() {
    int (*func_ptr)() = disassemble_instruction;
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
