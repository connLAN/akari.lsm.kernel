BUILD_FILES = akari-init

all: $(BUILD_FILES)

install: all
	mkdir -p $(INSTALLDIR)/sbin
	chmod 700 $(BUILD_FILES)
	chown -R root:root .
	cp -af --remove-destination $(BUILD_FILES) $(INSTALLDIR)/sbin/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
