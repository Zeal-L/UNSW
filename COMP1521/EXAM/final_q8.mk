EXERCISES	+= final_q8
CLEAN_FILES	+= final_q8 final_q8.o

final_q8:	final_q8.o final_q8_main.o
final_q8.o:	final_q8.c final_q8.h final_q8_opcodes.h
final_q8_main.o: final_q8_main.c final_q8.h
