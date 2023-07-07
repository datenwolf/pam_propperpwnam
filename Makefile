CFLAGS ?= -Wall -O2 -fPIC
LDFLAGS ?= -shared
LDLIBS ?= -lpam
DESTDIR ?=
INSTALL ?= install -D -p -o root -g root -m 644
SECUREDIR ?= /lib/security

.PHONY: all clean install

.SUFFIXES: .c .so

.c.so:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

all: pam_propperpwnam.so

clean:
	-rm *.so

install: pam_propperpwnam.so
	$(INSTALL) $< $(DESTDIR)$(SECUREDIR)/$<
