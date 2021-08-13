// COMP1521 21T2 ... final exam, question 9

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "final_q8.h"
#include "final_q8_opcodes.h"


void ifOP_SPECIAL(Instruction i, Word insn_word, int las_six) {
	i.uses_rd = 1;
	i.uses_rs = 1;
	i.uses_imm = 0;
	i.uses_rt = 1;
	i.uses_base = 0;

	uint32_t s1 = ((insn_word >> 21) & 0x1f),
			t1 = ((insn_word >> 16) & 0x1f),
			d1 = ((insn_word >> 11) & 0x1f);

	i.rs = s1;
	i.rt = t1;
	i.rd = d1;

	if (las_six == OP_SPECIAL_ADD) {
		char *temp = "add";
		strcpy(i.op, temp);

	} else if (las_six == OP_SPECIAL_ADDU) {
		char *temp = "addu";
		strcpy(i.op, temp);

	} else if (las_six == OP_SPECIAL_SUB) {
		char *temp = "sub";
		strcpy(i.op, temp);

	} else if (las_six == OP_SPECIAL_SUBU) {
		char *temp = "subu";
		strcpy(i.op, temp);
	}
}

void ifOP_ADDI(Instruction i, Word insn_word) {
	char *temp = "addi";
	strcpy(i.op, temp);
	uint32_t s1 = (insn_word >> 21) & 0x1f,
			 t1 = (insn_word >> 16) & 0x1f,
			 imm = insn_word & 0xffff;

	i.rs = s1;
	i.rt = t1;
	i.imm = imm;

	i.uses_imm = 1;
	i.uses_rd = 0;
	i.uses_rs = 1;
	i.uses_rt = 1;
	i.uses_base = 0;
}

void ifOP_ADDIU(Instruction i, Word insn_word) {
	char *temp = "addiu";
	strcpy(i.op, temp);
	uint32_t s1 = (insn_word >> 21) & 0x1f,
			 t1 = (insn_word >> 16) & 0x1f,
			 imm = insn_word & 0xffff;


	i.rs = s1;
	i.rt = t1;
	i.imm = imm;


	i.uses_rd = 0;
	i.uses_rt = 1;
	i.uses_imm = 1;
	i.uses_rs = 1;
	i.uses_base = 0;
}

void ifOP_LB(Instruction i, Word insn_word) {
	char *temp = "lb";
	strcpy(i.op, temp);
	uint32_t t1 = (insn_word >> 16) & 0x1f,
			 b = (insn_word >> 21) & 0x1f,
			 imm = insn_word & 0xffff;

	i.base = b;
	i.rt = t1;
	i.imm = imm;

	i.uses_imm = 1;
	i.uses_rt = 1;
	i.uses_rd = 0;
	i.uses_rs = 0;
	i.uses_base = 1;
}

void ifOP_LW(Instruction i, Word insn_word) {
	char *temp = "lw";
	strcpy(i.op, temp);
	uint32_t t1 = (insn_word >> 16) & 0x1f,
			 b = (insn_word >> 21) & 0x1f,
			 imm = insn_word & 0xffff;
			 
	i.base = b;
	i.rt = t1;
	i.imm = imm;


	i.uses_imm = 1;
	i.uses_rt = 1;
	i.uses_rd = 0;
	i.uses_rs = 0;
	i.uses_base = 1;
}

Instruction
decode_instruction (Word insn_word)
{
	Instruction ins = { .op = "[unknown]" };

	int firs_six = ((insn_word >> 26) & 0x3f);
	int las_six = insn_word & 0x3f;

	if (firs_six == OP_SPECIAL) {
		ifOP_SPECIAL(ins, insn_word, las_six);

	} else if (firs_six == OP_ADDI) {
		ifOP_ADDI(ins, insn_word);

	} else if (firs_six == OP_ADDIU) {
		ifOP_ADDIU(ins, insn_word);

	} else if (firs_six == OP_LB) {
		ifOP_LB(ins, insn_word);

	} else if (firs_six == OP_LW) {
		ifOP_LW(ins, insn_word);
	}

	return ins;
}
