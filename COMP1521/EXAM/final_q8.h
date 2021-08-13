// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 8

#ifndef FINAL_Q8_H_
#define FINAL_Q8_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define INSN_LENGTH 16

typedef uint32_t Word;

// `enum Register' is an enumeration of all register names/numbers.
typedef enum Register {
	r0,  r1,  r2,  r3,  r4,  r5,  r6,  r7,
	r8,  r9,  r10, r11, r12, r13, r14, r15,
	r16, r17, r18, r19, r20, r21, r22, r23,
	r24, r25, r26, r27, r28, r29, r30, r31
} Register;

// `struct Instruction' is a structure that describes an instruction.
// An instruction has a mnemonic or opcode, stored in `.op', and a
// series of operands.
typedef struct Instruction {
	char op[INSN_LENGTH];
	bool uses_rs :1, uses_rt :1, uses_rd :1, uses_base :1, uses_imm :1;
	Register rs, rt, rd, base;
	Word imm;
} Instruction;

void show_instruction (Instruction insn);
Instruction decode_instruction (Word insn_word);

#endif /* !defined(FINAL_Q8_H_) */
