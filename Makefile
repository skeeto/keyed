CC      = cc
CFLAGS  = -std=c99 -Wall -Wextra -Wno-type-limits -O3 -ggdb3
LDFLAGS =
LDLIBS  =

keyed: keyed.c chacha20.h argon2.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ keyed.c $(LDLIBS)

clean:
	rm -f keyed
