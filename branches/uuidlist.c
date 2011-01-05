#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#define true  1
#define false 0

struct uuid_task_entry {
	pid_t pid;
	char *name;
	char *uuid;
};

static struct uuid_task_entry *uuid_task_list = NULL;
static int uuid_task_list_len = 0;

static int uuid_task_entry_compare(const void *a, const void *b)
{
	const struct uuid_task_entry *a0 = (struct uuid_task_entry *) a;
	const struct uuid_task_entry *b0 = (struct uuid_task_entry *) b;
	int ret = strcmp(a0->uuid, b0->uuid);
	if (!ret)
		ret = a0->pid - b0->pid;
	return ret;
}

static char *uuid_get_name(const pid_t pid)
{
	char buffer[1024];
	FILE *fp;
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/status", pid);
	fp = fopen(buffer, "r");
	if (fp) {
		static const int offset = sizeof(buffer) / 6;
		while (memset(buffer, 0, sizeof(buffer)),
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			if (!strncmp(buffer, "Name:\t", 6)) {
				char *cp = buffer + 6;
				memmove(buffer, cp, strlen(cp) + 1);
				cp = strchr(buffer, '\n');
				if (cp)
					*cp = '\0';
				break;
			}
		}
		fclose(fp);
		if (buffer[0] && strlen(buffer) < offset - 1) {
			const char *src = buffer;
			char *dest = buffer + offset;
			while (1) {
				unsigned char c = *src++;
				if (!c) {
					*dest = '\0';
					break;
				}
				if (c == '\\') {
					c = *src++;
					if (c == '\\') {
						memmove(dest, "\\\\", 2);
						dest += 2;
					} else if (c == 'n') {
						memmove(dest, "\\012", 4);
						dest += 4;
					} else {
						break;
					}
				} else if (c > ' ' && c <= 126) {
					*dest++ = c;
				} else {
					*dest++ = '\\';
					*dest++ = (c >> 6) + '0';
					*dest++ = ((c >> 3) & 7) + '0';
					*dest++ = (c & 7) + '0';
				}
			}
			return strdup(buffer + offset);
		}
	}
	return NULL;
}

static void uuid_read_process_list(_Bool show_all)
{
	static char line[256];
	int status_fd = open("/proc/uuid_status", O_RDWR);
	DIR *dir = opendir("/proc/");
	while (uuid_task_list_len) {
		uuid_task_list_len--;
		free((void *) uuid_task_list[uuid_task_list_len].name);
		free((void *) uuid_task_list[uuid_task_list_len].uuid);
	}
	if (status_fd == EOF || !dir) {
		if (status_fd != EOF)
			close(status_fd);
		if (dir)
			closedir(dir);
		return;
	}
	while (1) {
		char *name;
		char *uuid;
		int ret_ignored;
		unsigned int pid = 0;
		char buffer[128];
		struct dirent *dent = readdir(dir);
		if (!dent)
			break;
		if (dent->d_type != DT_DIR ||
		    sscanf(dent->d_name, "%u", &pid) != 1 || !pid)
			continue;
		memset(buffer, 0, sizeof(buffer));
		if (!show_all) {
			char test[16];
			snprintf(buffer, sizeof(buffer) - 1,
				 "/proc/%u/exe", pid);
			if (readlink(buffer, test, sizeof(test)) <= 0 &&
			    errno == ENOENT)
				continue;
		}
		name = uuid_get_name(pid);
		if (!name)
			name = strdup("<UNKNOWN>");
		if (!name)
			exit(1);
		snprintf(buffer, sizeof(buffer) - 1, "%u\n", pid);
		ret_ignored = write(status_fd, buffer, strlen(buffer));
		memset(line, 0, sizeof(line));
		ret_ignored = read(status_fd, line, sizeof(line) - 1);
		if (sscanf(line, "%u", &pid) != 1) {
			free(name);
			continue;
		}
		uuid = strchr(line, ' ');
		if (uuid)
			uuid = strdup(uuid + 1);
		if (!uuid)
			exit(1);
		uuid_task_list = realloc(uuid_task_list,
					(uuid_task_list_len + 1) *
					sizeof(struct uuid_task_entry));
		if (!uuid_task_list)
			exit(1);
		memset(&uuid_task_list[uuid_task_list_len], 0,
		       sizeof(uuid_task_list[0]));
		uuid_task_list[uuid_task_list_len].pid = pid;
		uuid_task_list[uuid_task_list_len].name = name;
		uuid_task_list[uuid_task_list_len].uuid = uuid;
		uuid_task_list_len++;
	}
	closedir(dir);
	close(status_fd);
	qsort(uuid_task_list, uuid_task_list_len,
	      sizeof(struct uuid_task_entry), uuid_task_entry_compare);
}

int main(int argc, char *argv[])
{
	static _Bool show_all = false;
	int i;
	if (argc > 1) {
		if (strcmp(argv[1], "-a")) {
			fprintf(stderr, "Usage: %s [-a]\n", argv[0]);
			return 0;
		}
		show_all = true;
	}
	uuid_read_process_list(show_all);
	if (!uuid_task_list_len) {
		fprintf(stderr, "You can't use this command for this kernel."
			"\n");
		return 1;
	}
	printf("ProcessID  Name             UUID\n");
	printf("---------- ---------------- "
	       "------------------------------------\n");
	for (i = 0; i < uuid_task_list_len; i++) {
		printf("%10u %16s %s", uuid_task_list[i].pid,
		       uuid_task_list[i].name, uuid_task_list[i].uuid);
	}
	while (uuid_task_list_len) {
		uuid_task_list_len--;
		free(uuid_task_list[uuid_task_list_len].name);
		free(uuid_task_list[uuid_task_list_len].uuid);
	}
	free(uuid_task_list);
	uuid_task_list = NULL;
	return 0;
}
