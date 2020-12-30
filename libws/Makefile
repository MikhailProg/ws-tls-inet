CFLAGS  := -pipe -Wall -Wextra
ARFLAGS := rv
OS      := $(shell uname -s)
TARGET  := wscat

.PHONY: all clean

ifdef M32
  CFLAGS  += -m32
  LDFLAGS += -m32
endif

ifdef DEBUG
  CFLAGS += -O0 -g
else
  CFLAGS += -O2 -DNDEBUG
  ifneq "$(OS)" "Darwin"
    LDFLAGS += -s
  endif
endif

ifdef IOFUZZ
  CFLAGS += -DIOFUZZ
endif

all: $(TARGET)

inet.o: inet.c inet.h
libinet.a: libinet.a(inet.o)

base64.o: base64.c base64.h
sha1.o: sha1.c sha1.h
ws.o: ws.c ws.h
libws.a: libws.a(ws.o) libws.a(sha1.o) libws.a(base64.o)

wscat.o: wscat.c libinet.a libws.a common.h 

wscat: LDLIBS  += -linet -lws
wscat: LDFLAGS += -L.

clean:
	rm -f $(TARGET) *.a *.o

