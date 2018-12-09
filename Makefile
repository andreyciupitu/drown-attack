CFLAGS=-I$(SSL_PREFIX)/include
LDFLAGS=-Wall -L $(SSL_PREFIX)/lib -lssl -lcrypto -ldl -lm

all: oracle

oracle: oracle.o
	gcc -o $@ $^ $(LDFLAGS)

oracle.o: oracle.c
	gcc -c -o $@ $^ $(CFLAGS)

clean:
	rm -f oracle oracle.o