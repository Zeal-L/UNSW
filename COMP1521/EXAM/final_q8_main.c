// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 8

#include "final_q8.h"

#ifdef main
#undef main
#endif

// The main entry point for the instruction decoder.
int
main (int argc, char *argv[])
{
	if (argc < 2) {
		fprintf (stderr, "usage: %s <instruction...>\n", argv[0]);
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; i++) {
		Word insn_word = strtol (argv[i], NULL, 16);
		Instruction insn = decode_instruction (insn_word);
		show_instruction (insn);
	}

	return EXIT_SUCCESS;
}

// Print out an instruction in a vaguely pretty way.
void
show_instruction (Instruction insn)
{
	const char *register_names[] = {
		[r0 ] = "zero",
		[r1 ] = "at",
		[r2 ] = "v0", [r3 ] = "v1",
		[r4 ] = "a0", [r5 ] = "a1", [r6 ] = "a2", [r7 ] = "a3",
		[r8 ] = "t0", [r9 ] = "t1", [r10] = "t2", [r11] = "t3",
		[r12] = "t4", [r13] = "t5", [r14] = "t6", [r15] = "t7",
		[r16] = "s0", [r17] = "s1", [r18] = "s2", [r19] = "s3",
		[r20] = "s4", [r21] = "s5", [r22] = "s6", [r23] = "s7",
		[r24] = "t8", [r25] = "t9",
		[r26] = "k0", [r27] = "k1",
		[r28] = "gp",
		[r29] = "sp",
		[r30] = "fp",
		[r31] = "ra"
	};

	// Print opcode.
	printf ("\t%s", insn.op);

	// Only print a tab if there will be operands.
	if (
		insn.uses_rd || insn.uses_rs || insn.uses_rt ||
		insn.uses_imm || insn.uses_base
	)
		printf ("\t");

	// Print operands; some instructions don't have certain fields,
	// so we check to see whether we should print that field.
	// (Working out where to put commas is fiddly, so we skip it :-)
	if (insn.uses_rd)
		printf (" $%s", register_names[insn.rd]);
	if (insn.uses_rd && insn.uses_rs)
		printf (" $%s", register_names[insn.rs]);
	if (insn.uses_rt)
		printf (" $%s", register_names[insn.rt]);
	if ((!insn.uses_rd) && insn.uses_rs)
		printf (" $%s", register_names[insn.rs]);
	if (insn.uses_imm)
		printf (" %d", insn.imm);
	if (insn.uses_base)
		printf ("($%s)", register_names[insn.base]);

	// And a newline to finish.
	printf ("\n");
}
