
CC=gcc
CFLAGS=-I include
LDFLAGS=-Llib -lssh -lcrypto -lrt

.PHONY: all 
all: time_ssh_auth

time_ssh_auth: time_ssh_auth.c Makefile
	$(CC) $(CFLAGS) -o time_ssh_auth time_ssh_auth.c $(LDFLAGS)

.PHONY: clean
clean:
	rm -f core time_ssh_auth.o time_ssh_auth

