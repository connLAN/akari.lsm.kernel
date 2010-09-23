BUILD_FILES = convert-exec-param convert-audit-log akari-editpolicy-agent init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/akari
	chmod 755 $(INSTALLDIR)/usr/lib/akari
	chown -R root:root .
	cp -af --remove-destination $(BUILD_FILES) akaritools.conf ../README.akari ../COPYING.akari $(INSTALLDIR)/usr/lib/akari/

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
