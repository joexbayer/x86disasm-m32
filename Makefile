all:
	gcc disasm32.c -o disasm32.o -m32 -g
	./disasm32.o