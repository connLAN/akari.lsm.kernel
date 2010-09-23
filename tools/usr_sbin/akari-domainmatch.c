/*
 * akari-domainmatch.c
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
	char buffer[16384];
	_Bool flag = 0;
	static char *domain = NULL;
	FILE *fp;
	if (argc != 2) {
		printf("%s string_to_find\n\n", argv[0]);
		return 0;
	}
	fp = fopen(AKARI_PROC_POLICY_DOMAIN_POLICY, "r");
	if (!fp) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8) &&
		    (buffer[8] == ' ' || !buffer[8])) {
			free(domain);
			domain = strdup(buffer);
			if (!domain)
				akari_out_of_memory();
			flag = 0;
			continue;
		}
		if (strstr(buffer, argv[1])) {
			if (!flag)
				printf("\n%s\n", domain);
			flag = 1;
			printf("%s\n", buffer);
		}
	}
	fclose(fp);
	free(domain);
	return 0;
}
