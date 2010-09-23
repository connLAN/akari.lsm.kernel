/*
 * akari-setlevel.c
 *
 * AKARI's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "akaritools.h"

int main(int argc, char *argv[])
{
	const char *policy_file = AKARI_PROC_POLICY_PROFILE;
	int i;
	int fd;
	char c;
	if (access(AKARI_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr, "You can't use this command for this "
			"kernel.\n");
		return 1;
	}
	fd = open(policy_file, O_RDWR);
	if (fd == EOF) {
		fprintf(stderr, "Can't open %s\n", policy_file);
		return 1;
	} else if (write(fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", AKARI_PROC_POLICY_MANAGER);
		return 1;
	}
	if (argc == 1) {
		printf("<<< Access Control Status >>>\n");
		while (read(fd, &c, 1) == 1)
			putchar(c);
	} else {
		FILE *fp = fdopen(fd, "r+");
		if (!fp) {
			fprintf(stderr, "Can't open %s\n", policy_file);
			close(fd);
			return 1;
		}
		for (i = 1; i < argc; i++) {
			char *cp = strchr(argv[i], '=');
			fprintf(fp, "%s\n", argv[i]);
			if (cp)
				*(cp + 1) = '\0';
		}
		fflush(fp);
		akari_get();
		while (true) {
			char *line = akari_freadline(fp);
			if (!line)
				break;
			for (i = 1; i < argc; i++) {
				if (strncmp(line, argv[i], strlen(argv[i])))
					continue;
				printf("%s\n", line);
				break;
			}
		}
		akari_put();
		fclose(fp);
	}
	close(fd);
	return 0;
}
