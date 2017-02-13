# Makefile for gls v1.0

CC=gcc
CFLAGS=-Wall

# Link with OpenSSL
LDFLAGS=-lssl -lcrypto

all: gls

gls: gls.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean: 
	rm -f gls
