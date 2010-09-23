/*
 * akari-editpolicy-agent.c
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <dirent.h>

static _Bool wait_data(const int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN};
	poll(&pfd, 1, -1);
	return 1;
}

static void show_tasklist(FILE *fp, const _Bool show_all)
{
	int status_fd = open(".process_status", O_RDWR);
	DIR *dir = opendir("/proc/");
	if (status_fd == EOF || !dir) {
		if (status_fd != EOF)
			close(status_fd);
		if (dir)
			closedir(dir);
		return;
	}
	fputc(0, fp);
	while (1) {
		FILE *status_fp;
		pid_t ppid = 1;
		char *name = NULL;
		char buffer[1024];
		char test[16];
		unsigned int pid;
		struct dirent *dent = readdir(dir);
		if (!dent)
			break;
		if (dent->d_type != DT_DIR ||
		    sscanf(dent->d_name, "%u", &pid) != 1 || !pid)
			continue;
		memset(buffer, 0, sizeof(buffer));
		if (!show_all) {
			snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/exe",
				 pid);
			if (readlink(buffer, test, sizeof(test)) <= 0)
				continue;
		}
		snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/status", pid);
		status_fp = fopen(buffer, "r");
		if (status_fp) {
			while (memset(buffer, 0, sizeof(buffer)),
			       fgets(buffer, sizeof(buffer) - 1, status_fp)) {
				if (!strncmp(buffer, "Name:\t", 6)) {
					char *cp = buffer + 6;
					memmove(buffer, cp, strlen(cp) + 1);
					cp = strchr(buffer, '\n');
					if (cp)
						*cp = '\0';
					name = strdup(buffer);
				}
				if (sscanf(buffer, "PPid: %u", &ppid) == 1)
					break;
			}
			fclose(status_fp);
		}
		snprintf(buffer, sizeof(buffer) - 1, "%u\n", pid);
		write(status_fd, buffer, strlen(buffer));
		memset(buffer, 0, sizeof(buffer));
		read(status_fd, buffer, sizeof(buffer));
		if (!buffer[0])
			continue;
		fprintf(fp, "PID=%u PPID=%u NAME=", pid, ppid);
		if (name) {
			const char *cp = name;
			while (1) {
				unsigned char c = *cp++;
				if (!c)
					break;
				if (c == '\\') {
					c = *cp++;
					if (c == '\\')
						fprintf(fp, "\\\\");
					else if (c == 'n')
						fprintf(fp, "\\012");
					else
						break;
				} else if (c > ' ' && c <= 126) {
					fputc(c, fp);
				} else {
					fprintf(fp, "\\%c%c%c",
						(c >> 6) + '0',
						((c >> 3) & 7) + '0',
						(c & 7) + '0');
				}
			}
			free(name);
		} else {
			fprintf(fp, "<UNKNOWN>");
		}
		fputc('\n', fp);
		fwrite(buffer, strlen(buffer), 1, fp);
		while (1) {
			int len = read(status_fd, buffer, sizeof(buffer));
			if (len <= 0)
				break;
			fwrite(buffer, len, 1, fp);
		}
		fputc('\n', fp);
	}
	fputc(0, fp);
	closedir(dir);
	close(status_fd);
	fflush(fp);
}

static void handle_stream(const int client, const char *filename)
{
	const int fd = open(filename, O_RDONLY);
	if (fd == EOF)
		return;
	/* Return \0 to indicate success. */
	write(client, "", 1);
	while (wait_data(fd)) {
		char buffer[4096];
		const int len = read(fd, buffer, sizeof(buffer));
		if (!len)
			continue;
		if (len == EOF || write(client, buffer, len) != len)
			break;
	}
	close(fd);
}

static void handle_query(const int client)
{
	const int fd = open("query", O_RDWR);
	if (fd == EOF)
		return;
	/* Return \0 to indicate success. */
	write(client, "", 1);
	while (wait_data(client)) {
		char buffer[4096];
		int len = recv(client, buffer, sizeof(buffer), MSG_DONTWAIT);
		int nonzero_len;
		if (len <= 0)
			break;
restart:
		for (nonzero_len = 0 ; nonzero_len < len; nonzero_len++)
			if (!buffer[nonzero_len])
				break;
		if (nonzero_len) {
			if (write(fd, buffer, nonzero_len) != nonzero_len)
				break;
		} else {
			while (wait_data(fd)) {
				char buffer2[4096];
				const int len = read(fd, buffer2,
						     sizeof(buffer2));
				if (!len)
					continue;
				if (len == EOF ||
				    write(client, buffer2, len) != len) {
					shutdown(client, SHUT_RDWR);
					break;
				}
				if (!buffer2[len - 1])
					break;
			}
			nonzero_len = 1;
		}
		len -= nonzero_len;
		memmove(buffer, buffer + nonzero_len, len);
		if (len)
			goto restart;
	}
	close(fd);
}

static _Bool verbose = 0;

static void handle_policy(const int client, const char *filename)
{
	char *cp = strrchr(filename, '/');
	int fd = open(cp ? cp + 1 : filename, O_RDWR);
	if (fd == EOF)
		goto out;
	/* Return \0 to indicate success. */
	if (write(client, "", 1) != 1)
		goto out;
	if (verbose) {
		write(2, "opened ", 7);
		write(2, filename, strlen(filename));
		write(2, "\n", 1);
	}
	while (wait_data(client)) {
		char buffer[4096];
		int len = recv(client, buffer, sizeof(buffer), MSG_DONTWAIT);
		int nonzero_len;
		if (len <= 0)
			break;
restart:
		for (nonzero_len = 0 ; nonzero_len < len; nonzero_len++)
			if (!buffer[nonzero_len])
				break;
		if (nonzero_len) {
			if (write(fd, buffer, nonzero_len) != nonzero_len)
				break;
			if (verbose)
				write(1, buffer, nonzero_len);
		} else {
			while (1) {
				char buffer2[4096];
				const int len = read(fd, buffer2,
						     sizeof(buffer2));
				if (len == 0)
					break;
				/* Don't send \0 because it is EOF marker. */
				if (len < 0 || memchr(buffer2, '\0', len) ||
				    write(client, buffer2, len) != len)
					goto out;
			}
			/* Return \0 to indicate EOF. */
			if (write(client, "", 1) != 1)
				goto out;
			nonzero_len = 1;
		}
		len -= nonzero_len;
		memmove(buffer, buffer + nonzero_len, len);
		if (len)
			goto restart;
	}
 out:
	if (verbose)
		write(2, "disconnected\n", 13);
}

static void do_child(const int client)
{
	int i;
	char buffer[1024];
	/* Read filename. */
	for (i = 0; i < sizeof(buffer); i++) {
		if (read(client, buffer + i, 1) != 1)
			goto out;
		if (!buffer[i])
			break;
	}
	if (!memchr(buffer, '\0', sizeof(buffer)))
		goto out;
	if (!strcmp(buffer, "proc:query"))
		handle_query(client);
	else if (!strcmp(buffer, "proc:grant_log") ||
		 !strcmp(buffer, "proc:reject_log"))
		handle_stream(client, buffer + 5);
	else if (!strncmp(buffer, "proc:", 5)) {
		/* Open /proc/\$/ for reading. */
		FILE *fp = fdopen(client, "w");
		if (fp) {
			show_tasklist(fp, !strcmp(buffer + 5,
						  "all_process_status"));
			fclose(fp);
		}
	} else
		handle_policy(client, buffer);
 out:
	close(client);
}

int main(int argc, char *argv[])
{
	const int listener = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	char *port;
	if (chdir("/proc/akari/"))
		return 1;
	{
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--verbose"))
				continue;
			verbose = 1;
			argc--;
			for (; i < argc; i++)
				argv[i] = argv[i + 1];
			break;
		}
	}
	if (argc != 2) {
usage:
		fprintf(stderr, "%s listen_address:listen_port\n", argv[0]);
		return 1;
	}
	port = strchr(argv[1], ':');
	if (!port)
		goto usage;
	*port++ = '\0';
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(atoi(port));
	if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) ||
	    listen(listener, 5) ||
	    getsockname(listener, (struct sockaddr *) &addr, &size)) {
		close(listener);
		return 1;
	}
	{
		const unsigned int ip = ntohl(addr.sin_addr.s_addr);
		printf("Listening at %u.%u.%u.%u:%u\n",
		       (unsigned char) (ip >> 24), (unsigned char) (ip >> 16),
		       (unsigned char) (ip >> 8), (unsigned char) ip,
		       ntohs(addr.sin_port));
		fflush(stdout);
	}
	close(0);
	if (!verbose) {
		close(1);
		close(2);
	}
	signal(SIGCHLD, SIG_IGN);
	while (1) {
		socklen_t size = sizeof(addr);
		const int client = accept(listener, (struct sockaddr *) &addr,
					  &size);
		if (client == EOF) {
			if (verbose)
				fprintf(stderr, "accept() failed\n");
			continue;
		}
		switch (fork()) {
		case 0:
			close(listener);
			do_child(client);
			_exit(0);
		case -1:
			if (verbose)
				fprintf(stderr, "fork() failed\n");
			close(client);
			break;
		default:
			close(client);
		}
	}
	close(listener);
	return 1;
}
