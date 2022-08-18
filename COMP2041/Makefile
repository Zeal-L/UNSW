CC      = clang-11
CFLAGS  = -O3 -Wall
LDFLAGS = -lm
BINS    = main.o graphics.o world.o

game : $(BINS)
	$(CC) $(CFLAGS) -o game main.o graphics.o world.o

main.o : main.c graphics.h world.h
	$(CC) $(CFLAGS) -c main.c

graphics.o : graphics.c world.h 
	$(CC) $(CFLAGS) -c graphics.c

world.o : world.c world.h 
	$(CC) $(CFLAGS) -c world.c

clean: 
    rm -f game $(BINS)
