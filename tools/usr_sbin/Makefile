BUILD_FILES = akari-auditd akari-domainmatch akari-queryd akari-pstree akari-checkpolicy akari-editpolicy akari-findtemp akari-loadpolicy akari-patternize akari-savepolicy akari-setlevel akari-setprofile akari-sortpolicy akari-diffpolicy akari-selectpolicy

all: libakaritools.so $(BUILD_FILES)

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

akari-editpolicy: akaritools.h editpolicy*.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o akari-editpolicy editpolicy*.c -lncurses -lakaritools -L. -DCOLOR_ON || ln -f dummy akari-editpolicy

akari-queryd: akaritools.h akari-queryd.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o akari-queryd akari-queryd.c -lncurses -lakaritools -L. || ln -f dummy akari-queryd

libakaritools.so: akaritools.c akaritools.h
	$(CC) $(CFLAGS) -fPIC akaritools.c -shared -Wl,-soname,libakaritools.so.1 -o libakaritools.so.1.0.0
	ln -sf libakaritools.so.1.0.0 libakaritools.so

.c:
	$(CC) $(CFLAGS) -o $@ -lakaritools -L. $<

install: all
	mkdir -p $(INSTALLDIR)/usr/sbin $(INSTALLDIR)/usr/lib
	cp -af --remove-destination $(BUILD_FILES) $(INSTALLDIR)/usr/sbin/
	cp -ad --remove-destination libakaritools.so.1.0.0 $(INSTALLDIR)/usr/lib/
	ln -sf libakaritools.so.1.0.0 $(INSTALLDIR)/usr/lib/libakaritools.so.1

clean:
	rm -f -- $(BUILD_FILES) libakaritools.so*

.PHONY: clean install
