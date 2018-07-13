CC      = cc
CFLAGS  = -std=c99 -Wall -Wextra -O3
LDFLAGS =
LDLIBS  = -lsodium

keyed: keyed.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ keyed.c $(LDLIBS)

clean:
	rm -f keyed
