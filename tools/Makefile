INSTALLDIR = /

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

export CC
export CFLAGS
export INSTALLDIR

all:
	$(MAKE) -C sbin/ all
	$(MAKE) -C usr_sbin/ all
	$(MAKE) -C usr_lib_akari/ all

install: all
	$(MAKE) -C sbin/ install
	$(MAKE) -C usr_sbin/ install
	$(MAKE) -C usr_lib_akari/ install

clean:
	$(MAKE) -C sbin/ clean
	$(MAKE) -C usr_sbin/ clean
	$(MAKE) -C usr_lib_akari/ clean

.PHONY: clean install
