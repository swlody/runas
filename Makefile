CC=gcc
CFLAGS=-static -Wall

runas: runas.c
	$(CC) $(CFLAGS) runas.c -o runas

clean: 
	rm runas
