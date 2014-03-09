INSTALL         := install
USRBINDIR       := /usr/bin
USRDOCDIR       := /usr/share/doc
ifndef CFLAGS
CFLAGS          := -Wall -O2 -D_FORTIFY_SOURCE=2
endif

all: udplogger

udplogger: udplogger.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udplogger udplogger.c

install: all
	mkdir -p -m 0755 $(INSTALLDIR)$(USRBINDIR)
	$(INSTALL) -m 0755 udplogger $(INSTALLDIR)$(USRBINDIR)
	mkdir -p -m 0755 $(INSTALLDIR)$(USRDOCDIR)/udplogger/
	$(INSTALL) -m 0644 README COPYING $(INSTALLDIR)$(USRDOCDIR)/udplogger/

clean:
	rm -f -- udplogger

.PHONY: clean install
