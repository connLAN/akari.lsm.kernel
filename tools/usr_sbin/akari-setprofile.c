/*
 * akari-setprofile.c
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
	FILE *fp_in;
	FILE *fp_out;
	unsigned int profile = 0;
	_Bool recursive = false;
	int i;
	int start = 2;
	if (argc > 1 && !strcmp(argv[1], "-r")) {
		recursive = true;
		start = 3;
	}
	if (argc <= start || sscanf(argv[start - 1], "%u", &profile) != 1) {
		fprintf(stderr, "%s [-r] profile domainname [domainname ...]\n",
			argv[0]);
		return 0;
	}
	for (i = start; i < argc; i++)
		akari_normalize_line(argv[i]);
	{
		const int fd = open(AKARI_PROC_POLICY_DOMAIN_STATUS, O_RDWR);
		if (fd == EOF) {
			fprintf(stderr, "You can't run this command for this "
				"kernel.\n");
			return 1;
		} else if (write(fd, "", 0) != 0) {
			fprintf(stderr, "You need to register this program to "
				"%s to run this program.\n",
				AKARI_PROC_POLICY_MANAGER);
			return 1;
		}
		close(fd);
	}
	{
		_Bool profile_found = false;
		FILE *fp = fopen(AKARI_PROC_POLICY_PROFILE, "r");
		if (!fp) {
			fprintf(stderr, "Can't open policy file.\n");
			exit(1);
		}
		akari_get();
		while (true) {
			char *line = akari_freadline(fp);
			if (!line)
				break;
			if (atoi(line) != profile)
				continue;
			profile_found = true;
			break;
		}
		akari_put();
		fclose(fp);
		if (!profile_found) {
			fprintf(stderr, "Profile %u not defined.\n", profile);
			exit(1);
		}
	}
	fp_in = fopen(AKARI_PROC_POLICY_DOMAIN_STATUS, "r");
	fp_out = fopen(AKARI_PROC_POLICY_DOMAIN_STATUS, "w");
	if (!fp_in || !fp_out) {
		fprintf(stderr, "Can't open policy file.\n");
		exit(1);
	}
	akari_get();
	while (true) {
		char *cp;
		char *line = akari_freadline(fp_in);
		if (!line)
			break;
		cp = strchr(line, ' ');
		if (!cp)
			break;
		*cp++ = '\0';
		for (i = start; i < argc; i++) {
			const int len = strlen(argv[i]);
			if (strncmp(cp, argv[i], len))
				continue;
			if (!recursive) {
				if (cp[len])
					continue;
			} else {
				if (cp[len] && cp[len] != ' ')
					continue;
			}
			fprintf(fp_out, "%u %s\n", profile, cp);
			printf("%u %s\n", profile, cp);
		}
	}
	akari_put();
	fclose(fp_in);
	fclose(fp_out);
	return 0;
}
