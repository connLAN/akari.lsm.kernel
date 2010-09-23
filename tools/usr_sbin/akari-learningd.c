/*
 * akari-queryd.c
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

/* Utility functions */

#if 0
static _Bool akari_check_path_info(const char *buffer)
{
	_Bool modified = false;
	static struct akari_path_info *update_list = NULL;
	static int update_list_len = 0;
	char *sp = strdup(buffer);
	char *str = sp;
	const char *path_list[2] = {
		AKARI_PROC_POLICY_EXCEPTION_POLICY,
		AKARI_PROC_POLICY_DOMAIN_POLICY
	};
	if (!str)
		return false;
	while (true) {
		int i;
		char *cp = strsep(&sp, " ");
		if (!cp)
			break;
		for (i = 0; i < update_list_len; i++) {
			int j;
			struct akari_path_info old;
			/* TODO: split cp at upadte_list's depth. */
			old.name = cp;
			akari_fill_path_info(&old);
			if (!akari_path_matches_pattern(&old, &update_list[i]))
				continue;
			for (j = 0; j < 2; j++) {
				FILE *fp = fopen(path_list[j], "r+");
				if (!fp)
					continue;
				if (convert_path_info(fp, &update_list[i], cp))
					modified = true;
				fclose(fp);
			}
		}
	}
	free(str);
	return modified;
}
#endif

#if 0
static _Bool akari_convert_path_info(FILE *fp, const struct akari_path_info *pattern,
				   const char *new)
{
	_Bool modified = false;
	const char *cp = pattern->name;
	int depth = 0;
	while (*cp)
		if (*cp++ == '/')
			depth++;
	while (true) {
		int d = depth;
		char buffer[4096];
		char *cp;
		if (fscanf(fp, "%4095s", buffer) != 1)
			break;
		if (buffer[0] != '/')
			goto out;
		cp = buffer;
		while (*cp) {
			char c;
			struct akari_path_info old;
			_Bool matched;
			if (*cp != '/' || --d)
				continue;
			cp++;
			c = *cp;
			*cp = '\0';
			old.name = buffer;
			akari_fill_path_info(&old);
			matched = akari_path_matches_pattern(&old, pattern);
			*cp = c;
			if (matched) {
				fprintf(fp, "%s%s", new, cp);
				modified = true;
				buffer[0] = '\0';
				break;
			}
		}
out:
		fprintf(fp, "%s ", buffer);
	}
	return modified;
}
#endif

static int akari_query_fd = EOF;

static void akari_send_keepalive(void)
{
	static time_t previous = 0;
	time_t now = time(NULL);
	if (previous != now || !previous) {
		previous = now;
		write(akari_query_fd, "\n", 1);
	}
}

/* Vakaribles */

static FILE *akari_domain_fp = NULL;
static const int akari_buffer_len = 32768;
static char *akari_buffer = NULL;

/* Main functions */

static _Bool akari_handle_query(unsigned int serial)
{
	unsigned int pid;
	char *cp = strstr(akari_buffer, " (global-pid=");
	if (!cp || sscanf(cp + 13, "%u", &pid) != 1)
		goto out;
	cp = akari_buffer + strlen(akari_buffer);
	if (*(cp - 1) != '\n')
		goto out;
	*(cp - 1) = '\0';
	cp = strrchr(akari_buffer, '\n');
	if (!cp)
		goto out;
	//printf("%s", cp + 1);
	fprintf(akari_domain_fp, "select global-pid=%u\n%s\n", pid, cp + 1);
	fflush(akari_domain_fp);
	/* Write answer. */
	snprintf(akari_buffer, akari_buffer_len - 1, "A%u=%u\n", serial, 1);
	write(akari_query_fd, akari_buffer, strlen(akari_buffer));
	return true;
 out:
	printf("ERROR: Unsupported query.\n%s", akari_buffer);
	return false;
}

int main(int argc, char *argv[])
{
	akari_query_fd = open("/proc/akari/.query", O_RDWR);
	akari_domain_fp = fopen(AKARI_PROC_POLICY_DOMAIN_POLICY, "w");
	if (akari_query_fd == EOF) {
		fprintf(stderr,
			"You can't run this utility for this kernel.\n");
		return 1;
	} else if (write(akari_query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", AKARI_PROC_POLICY_MANAGER);
		return 1;
	}
	akari_send_keepalive();
	printf("Monitoring /proc/akari/.query .");
	printf(" Press Ctrl-C to terminate.\n\n");
	while (true) {
		fd_set rfds;
		unsigned int serial;
		char *cp;
		if (!akari_buffer) {
			akari_buffer = malloc(akari_buffer_len);
			if (!akari_buffer)
				break;
		}
		/* Wait for query. */
		FD_ZERO(&rfds);
		FD_SET(akari_query_fd, &rfds);
		select(akari_query_fd + 1, &rfds, NULL, NULL, NULL);
		if (!FD_ISSET(akari_query_fd, &rfds))
			continue;

		/* Read query. */
		memset(akari_buffer, 0, akari_buffer_len);
		if (read(akari_query_fd, akari_buffer, akari_buffer_len - 1) <= 0)
			continue;
		//printf("query=<%s>\n", akari_buffer);
		cp = strchr(akari_buffer, '\n');
		if (!cp)
			break;
		*cp = '\0';

		/* Get query number. */
		if (sscanf(akari_buffer, "Q%u", &serial) != 1)
			break;
		memmove(akari_buffer, cp + 1, strlen(cp + 1) + 1);
		if (akari_handle_query(serial))
			continue;
		break;
	}
	return 0;
}
