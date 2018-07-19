CC      = cc
CFLAGS  = -std=c99 -Wall -Wextra -O3 -ggdb3
LDFLAGS =
LDLIBS  = -lsodium

keyed: keyed.c chacha20.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ keyed.c $(LDLIBS)

clean:
	rm -f keyed
