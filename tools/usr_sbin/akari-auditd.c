/*
 * akari-auditd.c
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
#include <syslog.h>

#define AKARI_AUDITD_MAX_FILES 2

int main(int argc, char *argv[])
{
	const char *procfile_path[AKARI_AUDITD_MAX_FILES] = {
		AKARI_PROC_POLICY_GRANT_LOG,
		AKARI_PROC_POLICY_REJECT_LOG
	};
	int i;
	int fd_in[AKARI_AUDITD_MAX_FILES];
	FILE *fp_out[AKARI_AUDITD_MAX_FILES];
	const char *logfile_path[2] = { NULL, NULL };

	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (!logfile_path[0])
				logfile_path[0] = ptr;
			else if (!logfile_path[1])
				logfile_path[1] = ptr;
			else
				goto usage;
		} else if (cp) {
			*cp++ = '\0';
			if (akari_network_mode)
				goto usage;
			akari_network_ip = inet_addr(ptr);
			akari_network_port = htons(atoi(cp));
			akari_network_mode = true;
			if (!akari_check_remote_host())
				return 1;
			procfile_path[0] = "proc:grant_log";
			procfile_path[1] = "proc:reject_log";
		} else
			goto usage;
	}
	if (!logfile_path[1])
		goto usage;
	if (akari_network_mode)
		goto start;
	if (access(procfile_path[0], R_OK) || access(procfile_path[1], R_OK)) {
		fprintf(stderr, "You can't run this daemon for this kernel.\n");
		return 0;
	}
	{ /* Get exclusive lock. */
		int fd = open("/proc/self/exe", O_RDONLY);
		if (flock(fd, LOCK_EX | LOCK_NB) == EOF)
			return 0;
	}
 start:
	umask(077);
	for (i = 0; i < AKARI_AUDITD_MAX_FILES; i++) {
		fp_out[i] = fopen(logfile_path[i], "a");
		if (!fp_out[i]) {
			fprintf(stderr, "Can't open %s for writing.\n",
				logfile_path[i]);
			return 1;
		}
	}
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (setsid() == EOF) {
		fprintf(stderr, "Can't setsid()\n");
		return 1;
	}
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (chdir("/")) {
		fprintf(stderr, "Can't chdir()\n");
		return 1;
	}
	close(0);
	close(1);
	close(2);
	openlog("akari-auditd", 0,  LOG_USER);
	for (i = 0; i < AKARI_AUDITD_MAX_FILES; i++) {
		if (akari_network_mode)
			fd_in[i] = akari_open_stream(procfile_path[i]);
		else
			fd_in[i] = open(procfile_path[i], O_RDONLY);
		if (fd_in[i] == EOF) {
			syslog(LOG_WARNING, "Can't open %s for reading.\n",
			       procfile_path[i]);
			return 1;
		}
	}
	syslog(LOG_WARNING, "Started.\n");
	while (true) {
		char buffer[32768];
		fd_set rfds;
		FD_ZERO(&rfds);
		for (i = 0; i < AKARI_AUDITD_MAX_FILES; i++)
			FD_SET(fd_in[i], &rfds);
		/* Wait for data. */
		if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) == EOF)
			break;
		for (i = 0; i < AKARI_AUDITD_MAX_FILES; i++) {
			time_t stamp;
			char *cp;
			if (!FD_ISSET(fd_in[i], &rfds))
				continue;
			memset(buffer, 0, sizeof(buffer));
			if (akari_network_mode) {
				int j;
				for (j = 0; j < sizeof(buffer) - 1; j++) {
					if (read(fd_in[i], buffer + j, 1) != 1)
						goto out;
					if (!buffer[j])
						break;
				}
				if (j == sizeof(buffer) - 1)
					goto out;
			} else
				if (read(fd_in[i], buffer, sizeof(buffer) - 1)
				    < 0)
					continue;
			/* Open destination file. */
			if (access(logfile_path[i], F_OK)) {
				fclose(fp_out[i]);
				fp_out[i] = fopen(logfile_path[i], "a");
				if (!fp_out[i]) {
					syslog(LOG_WARNING,
					       "Can't open %s for writing.\n",
					       logfile_path[i]);
					goto out;
				}
			}
			cp = strchr(buffer, ' ');
			if (sscanf(buffer, "#timestamp=%lu", &stamp) == 1
			    && cp) {
				struct tm *tm = localtime(&stamp);
				fprintf(fp_out[i],
					"#%04d-%02d-%02d %02d:%02d:%02d#%s\n",
					tm->tm_year + 1900, tm->tm_mon + 1,
					tm->tm_mday, tm->tm_hour, tm->tm_min,
					tm->tm_sec, cp);
			} else
				fprintf(fp_out[i], "%s\n", buffer);
			fflush(fp_out[i]);
		}
	}
out:
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 0;
usage:
	fprintf(stderr, "%s grant_log_file reject_log_file "
		"[remote_ip:remote_port]\n"
		"  These files may /dev/null, if needn't to be saved."
		"\n", argv[0]);
	return 0;
}
