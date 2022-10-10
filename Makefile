CFLAGS  := -pipe -Wall -Wextra -O2 -Ilibws -DNDEBUG
# define _XOPEN_SOURCE for posix_openpt
# define _DEFAULT_SOURCE for NSIG (_XOPEN_SOURCE hides it)
CFLAGS  += -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600
LDFLAGS := -Llibws
LDLIBS  := -lgnutls -lws -linet
PWD     := $(shell pwd)

TARGETS := rdwr ws tls inet

.PHONY: all clean

ifdef WS_IO_FUZZ
  CFLAGS += -DWS_IO_FUZZ
endif

all: $(TARGETS)

rdwr.o: libws/libws.a

rdwr:

ws inet tls: rdwr
	ln -s $(PWD)/$< $@

libws/libws.a:
	make -C libws

clean:
	rm -f rdwr ws tls inet *.o
	make -C libws clean

