# x86disasm-m32
32bit x86 machine code disassembler.

## Simple and currently incomplete x86 disassembler for 32bit machine code.

## Currently dissasembles a function in the C code
    
```c
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


    printf("Disassembling function at address %p (%d)\n", func_ptr, length);
    size_t offset = 0;
    while (offset < length) {
        disassemble_instruction(binary_code, length, &offset);
    }

    return 0;
}
```

## Currently supported instructions:
# Supported Instructions

| Opcode | Mnemonic        | Description                               |
|--------|-----------------|-------------------------------------------|
| 0xf3   | endbr32         | End branch instruction                    |
| 0x0f b6| movzbl          | Move byte to double word with zero extend |
| 0x0f 84| test            | Logical compare                           |
| 0x90   | nop             | No operation                              |
| 0x55   | push %ebp       | Push EBP register onto stack              |
| 0x89   | mov             | Move data                                 |
| 0x83   | sub, add, cmp   | Subtract, add, compare                    |
| 0xe8   | call            | Call procedure                            |
| 0x05   | add             | Add immediate to EAX                      |
| 0xc7   | mov             | Move immediate to memory                  |
| 0x8b   | mov             | Move from memory to register              |
| 0xc9   | leave           | Restore stack frame                       |
| 0xc3   | ret             | Return from procedure                     |
| 0x53   | push %ebx       | Push EBX register onto stack              |
| 0xeb   | jmp short       | Jump short                                |
| 0x7e   | jle             | Jump if less or equal                     |
| 0x8d   | lea             | Load effective address                    |
| 0x52   | push %edx       | Push EDX register onto stack              |
| 0x01   | add             | Add                                      |
| 0x84   | test            | Logical compare                           |
| 0x75   | jne             | Jump if not equal                         |
| 0x3c   | cmp             | Compare AL with immediate                 |
| 0x81   | add             | Add immediate to memory/register          |
| 0x65   | gs              | Segment override GS                       |
| 0xa1   | mov             | Move from memory to EAX with segment override |
| 0x31   | xor             | Exclusive OR                              |
| 0xff   | inc, dec, call, jmp, push | Increment, decrement, call, jump, push |
| 0x50   | push %eax       | Push EAX register onto stack              |
| 0x3b   | cmp             | Compare                                  |
| 0x72   | jb              | Jump if below                             |
| 0x6a   | push            | Push immediate onto stack                 |
| 0x39   | cmp             | Compare                                  |
| 0x77   | ja              | Jump if above                             |
| 0xb8   | mov imm32, eax  | Move immediate to EAX                     |
| 0x33   | xor             | Exclusive OR with segment override GS     |
| 0x74   | je              | Jump if equal                             |
