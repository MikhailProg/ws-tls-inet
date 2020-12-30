CFLAGS  := -pipe -Wall -Wextra -O2 -Ilibws -DNDEBUG
LDFLAGS := -Llibws
LDLIBS  := -lgnutls -lws -linet
PWD     := $(shell pwd)

TARGETS := rdwr ws tls inet

.PHONY: all clean libws

all: $(TARGETS)

rdwr.o: libws

rdwr:

ws inet tls: rdwr
	ln -s $(PWD)/$< $@

libws:
	make -C libws

clean:
	rm -f rdwr ws tls inet *.o
	make -C libws clean

