/*
 * convert-audit-log.c
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char buffer[65536];
static char *cond = NULL;
static int cond_len = 0;

static void realloc_buffer(const int len)
{
	cond = realloc(cond, cond_len + len);
	if (!cond)
		exit(1);
}

static void handle_task_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		realloc_buffer(strlen(buffer) + 7);
		cond_len += sprintf(cond + cond_len, " task.%s", buffer);
	}
}

static void handle_path_condition(const char *path)
{
	const int len0 = strlen(path) + 2;
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		realloc_buffer(len0 + strlen(buffer));
		cond_len += sprintf(cond + cond_len, " %s%s", path, buffer);
	}
}

static void handle_argv_condition(void)
{
	int i = 0;
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")
	       && strcmp(buffer, "...")) {
		realloc_buffer(strlen(buffer) + 34);
		cond_len += sprintf(cond + cond_len, " exec.argv[%u]=%s", i++,
				    buffer);
	}
}

static void handle_envp_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")
	       && strcmp(buffer, "...")) {
		char *cp = strchr(buffer, '=');
		if (!cp)
			break;
		realloc_buffer(strlen(buffer) + 16);
		*cp++ = '\0';
		cond_len += sprintf(cond + cond_len, " exec.envp[%s\"]=\"%s",
				    buffer, cp);
	}
}

static void handle_exec_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		if (!strcmp(buffer, "argv[]={"))
			handle_argv_condition();
		else if (!strcmp(buffer, "envp[]={"))
			handle_envp_condition();
		else {
			realloc_buffer(strlen(buffer) + 7);
			cond_len += sprintf(cond + cond_len, " exec.%s",
					    buffer);
		}
	}
}

int main(int argc, char *argv[])
{
	char *domainname = NULL;
	memset(buffer, 0, sizeof(buffer));
	if (argc > 1) {
		fprintf(stderr, "Usage: %s < grant_log or reject_log\n",
			argv[0]);
		return 0;
	}
	while (fscanf(stdin, "%65534s", buffer) == 1) {
		if (!strcmp(buffer, "task={"))
			handle_task_condition();
		else if (!strcmp(buffer, "path1={"))
			handle_path_condition("path1.");
		else if (!strcmp(buffer, "path1.parent={"))
			handle_path_condition("path1.parent.");
		else if (!strcmp(buffer, "path2={"))
			handle_path_condition("path2.");
		else if (!strcmp(buffer, "path2.parent={"))
			handle_path_condition("path2.parent.");
		else if (!strcmp(buffer, "path2.parent={"))
			handle_path_condition("path2.parent.");
		else if (!strcmp(buffer, "exec={"))
			handle_exec_condition();
		else if (!strncmp(buffer, "symlink.target=", 15)) {
			realloc_buffer(strlen(buffer) + 2);
			cond_len += sprintf(cond + cond_len, " %s", buffer);
		} else if (!strcmp(buffer, "<kernel>")) {
			char *cp;
			if (!fgets(buffer, sizeof(buffer) - 1, stdin) ||
			    !strchr(buffer, '\n'))
				break;
			free(domainname);
			domainname = strdup(buffer);
			if (!domainname)
				break;
			if (!fgets(buffer, sizeof(buffer) - 1, stdin))
				break;
			cp = strchr(buffer, '\n');
			if (!cp)
				break;
			*cp = '\0';
			if (!strncmp(buffer, "use_profile ", 12) ||
			    !strncmp(buffer, "use_group ", 11)) {
				cond_len = 0;
				continue;
			}
			printf("<kernel>%s", domainname);
			printf("%s", buffer);
			if (cond_len) {
				printf("%s", cond);
				cond_len = 0;
			}
			putchar('\n');
		}
	}
	free(domainname);
	free(cond);
	return 0;
}
