/*
 * akari-checkpolicy.c
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

#define AKARI_MAX_PATHNAME_LEN             4000

enum akari_policy_type {
	AKARI_POLICY_TYPE_UNKNOWN,
	AKARI_POLICY_TYPE_DOMAIN_POLICY,
	AKARI_POLICY_TYPE_EXCEPTION_POLICY,
};

#define AKARI_VALUE_TYPE_DECIMAL     1
#define AKARI_VALUE_TYPE_OCTAL       2
#define AKARI_VALUE_TYPE_HEXADECIMAL 3

static int akari_parse_ulong(unsigned long *result, char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;
	if (*cp == '0') {
		char c = *(cp + 1);
		if (c == 'x' || c == 'X') {
			base = 16;
			cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8;
			cp++;
		}
	}
	*result = strtoul(cp, &ep, base);
	if (cp == ep)
		return 0;
	*str = ep;
	return base == 16 ? AKARI_VALUE_TYPE_HEXADECIMAL :
		(base == 8 ? AKARI_VALUE_TYPE_OCTAL : AKARI_VALUE_TYPE_DECIMAL);
}

static char *akari_find_condition_part(char *data)
{
	char *cp = strstr(data, " if ");
	if (cp) {
		while (1) {
			char *cp2 = strstr(cp + 3, " if ");
			if (!cp2)
				break;
			cp = cp2;
		}
		*cp = '\0';
		cp += 4;
	}
	return cp;
}

static unsigned int akari_line = 0;
static unsigned int akari_errors = 0;
static unsigned int akari_warnings = 0;

static _Bool akari_check_condition(char *condition)
{
	enum akari_conditions_index {
		AKARI_TASK_UID,             /* current_uid()   */
		AKARI_TASK_EUID,            /* current_euid()  */
		AKARI_TASK_SUID,            /* current_suid()  */
		AKARI_TASK_FSUID,           /* current_fsuid() */
		AKARI_TASK_GID,             /* current_gid()   */
		AKARI_TASK_EGID,            /* current_egid()  */
		AKARI_TASK_SGID,            /* current_sgid()  */
		AKARI_TASK_FSGID,           /* current_fsgid() */
		AKARI_TASK_PID,             /* sys_getpid()   */
		AKARI_TASK_PPID,            /* sys_getppid()  */
		AKARI_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
		AKARI_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
		AKARI_TYPE_IS_SOCKET,       /* S_IFSOCK */
		AKARI_TYPE_IS_SYMLINK,      /* S_IFLNK */
		AKARI_TYPE_IS_FILE,         /* S_IFREG */
		AKARI_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
		AKARI_TYPE_IS_DIRECTORY,    /* S_IFDIR */
		AKARI_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
		AKARI_TYPE_IS_FIFO,         /* S_IFIFO */
		AKARI_MODE_SETUID,          /* S_ISUID */
		AKARI_MODE_SETGID,          /* S_ISGID */
		AKARI_MODE_STICKY,          /* S_ISVTX */
		AKARI_MODE_OWNER_READ,      /* S_IRUSR */
		AKARI_MODE_OWNER_WRITE,     /* S_IWUSR */
		AKARI_MODE_OWNER_EXECUTE,   /* S_IXUSR */
		AKARI_MODE_GROUP_READ,      /* S_IRGRP */
		AKARI_MODE_GROUP_WRITE,     /* S_IWGRP */
		AKARI_MODE_GROUP_EXECUTE,   /* S_IXGRP */
		AKARI_MODE_OTHERS_READ,     /* S_IROTH */
		AKARI_MODE_OTHERS_WRITE,    /* S_IWOTH */
		AKARI_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
		AKARI_TASK_TYPE,            /* ((u8) task->akari_flags) &
					     AKARI_TASK_IS_EXECUTE_HANDLER */
		AKARI_TASK_EXECUTE_HANDLER, /* AKARI_TASK_IS_EXECUTE_HANDLER */
		AKARI_EXEC_REALPATH,
		AKARI_SYMLINK_TARGET,
		AKARI_PATH1_UID,
		AKARI_PATH1_GID,
		AKARI_PATH1_INO,
		AKARI_PATH1_MAJOR,
		AKARI_PATH1_MINOR,
		AKARI_PATH1_PERM,
		AKARI_PATH1_TYPE,
		AKARI_PATH1_DEV_MAJOR,
		AKARI_PATH1_DEV_MINOR,
		AKARI_PATH2_UID,
		AKARI_PATH2_GID,
		AKARI_PATH2_INO,
		AKARI_PATH2_MAJOR,
		AKARI_PATH2_MINOR,
		AKARI_PATH2_PERM,
		AKARI_PATH2_TYPE,
		AKARI_PATH2_DEV_MAJOR,
		AKARI_PATH2_DEV_MINOR,
		AKARI_PATH1_PARENT_UID,
		AKARI_PATH1_PARENT_GID,
		AKARI_PATH1_PARENT_INO,
		AKARI_PATH1_PARENT_PERM,
		AKARI_PATH2_PARENT_UID,
		AKARI_PATH2_PARENT_GID,
		AKARI_PATH2_PARENT_INO,
		AKARI_PATH2_PARENT_PERM,
		AKARI_MAX_CONDITION_KEYWORD,
		AKARI_NUMBER_UNION,
		AKARI_NAME_UNION,
		AKARI_ARGV_ENTRY,
		AKARI_ENVP_ENTRY
	};
	static const char *akari_condition_keyword[AKARI_MAX_CONDITION_KEYWORD] = {
		[AKARI_TASK_UID]             = "task.uid",
		[AKARI_TASK_EUID]            = "task.euid",
		[AKARI_TASK_SUID]            = "task.suid",
		[AKARI_TASK_FSUID]           = "task.fsuid",
		[AKARI_TASK_GID]             = "task.gid",
		[AKARI_TASK_EGID]            = "task.egid",
		[AKARI_TASK_SGID]            = "task.sgid",
		[AKARI_TASK_FSGID]           = "task.fsgid",
		[AKARI_TASK_PID]             = "task.pid",
		[AKARI_TASK_PPID]            = "task.ppid",
		[AKARI_EXEC_ARGC]            = "exec.argc",
		[AKARI_EXEC_ENVC]            = "exec.envc",
		[AKARI_TYPE_IS_SOCKET]       = "socket",
		[AKARI_TYPE_IS_SYMLINK]      = "symlink",
		[AKARI_TYPE_IS_FILE]         = "file",
		[AKARI_TYPE_IS_BLOCK_DEV]    = "block",
		[AKARI_TYPE_IS_DIRECTORY]    = "directory",
		[AKARI_TYPE_IS_CHAR_DEV]     = "char",
		[AKARI_TYPE_IS_FIFO]         = "fifo",
		[AKARI_MODE_SETUID]          = "setuid",
		[AKARI_MODE_SETGID]          = "setgid",
		[AKARI_MODE_STICKY]          = "sticky",
		[AKARI_MODE_OWNER_READ]      = "owner_read",
		[AKARI_MODE_OWNER_WRITE]     = "owner_write",
		[AKARI_MODE_OWNER_EXECUTE]   = "owner_execute",
		[AKARI_MODE_GROUP_READ]      = "group_read",
		[AKARI_MODE_GROUP_WRITE]     = "group_write",
		[AKARI_MODE_GROUP_EXECUTE]   = "group_execute",
		[AKARI_MODE_OTHERS_READ]     = "others_read",
		[AKARI_MODE_OTHERS_WRITE]    = "others_write",
		[AKARI_MODE_OTHERS_EXECUTE]  = "others_execute",
		[AKARI_TASK_TYPE]            = "task.type",
		[AKARI_TASK_EXECUTE_HANDLER] = "execute_handler",
		[AKARI_EXEC_REALPATH]        = "exec.realpath",
		[AKARI_SYMLINK_TARGET]       = "symlink.target",
		[AKARI_PATH1_UID]            = "path1.uid",
		[AKARI_PATH1_GID]            = "path1.gid",
		[AKARI_PATH1_INO]            = "path1.ino",
		[AKARI_PATH1_MAJOR]          = "path1.major",
		[AKARI_PATH1_MINOR]          = "path1.minor",
		[AKARI_PATH1_PERM]           = "path1.perm",
		[AKARI_PATH1_TYPE]           = "path1.type",
		[AKARI_PATH1_DEV_MAJOR]      = "path1.dev_major",
		[AKARI_PATH1_DEV_MINOR]      = "path1.dev_minor",
		[AKARI_PATH2_UID]            = "path2.uid",
		[AKARI_PATH2_GID]            = "path2.gid",
		[AKARI_PATH2_INO]            = "path2.ino",
		[AKARI_PATH2_MAJOR]          = "path2.major",
		[AKARI_PATH2_MINOR]          = "path2.minor",
		[AKARI_PATH2_PERM]           = "path2.perm",
		[AKARI_PATH2_TYPE]           = "path2.type",
		[AKARI_PATH2_DEV_MAJOR]      = "path2.dev_major",
		[AKARI_PATH2_DEV_MINOR]      = "path2.dev_minor",
		[AKARI_PATH1_PARENT_UID]     = "path1.parent.uid",
		[AKARI_PATH1_PARENT_GID]     = "path1.parent.gid",
		[AKARI_PATH1_PARENT_INO]     = "path1.parent.ino",
		[AKARI_PATH1_PARENT_PERM]    = "path1.parent.perm",
		[AKARI_PATH2_PARENT_UID]     = "path2.parent.uid",
		[AKARI_PATH2_PARENT_GID]     = "path2.parent.gid",
		[AKARI_PATH2_PARENT_INO]     = "path2.parent.ino",
		[AKARI_PATH2_PARENT_PERM]    = "path2.parent.perm",
	};
	//char *const start = condition;
	char *pos = condition;
	u8 left;
	u8 right;
	//int i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	if (*condition && condition[strlen(condition) - 1] == ' ')
		condition[strlen(condition) - 1] = '\0';
	if (!*condition)
		return true;
	pos = condition;
	while (pos) {
		char *eq;
		char *next = strchr(pos, ' ');
		int r_len;
		if (next)
			*next++ = '\0';
		if (!akari_correct_word(pos))
			goto out;
		eq = strchr(pos, '=');
		if (!eq)
			goto out;
		*eq = '\0';
		if (eq > pos && *(eq - 1) == '!')
			*(eq - 1) = '\0';
		r_len = strlen(eq + 1);
		if (!strncmp(pos, "exec.argv[", 10)) {
			pos += 10;
			if (!akari_parse_ulong(&left_min, &pos) || strcmp(pos, "]"))
				goto out;
			pos = eq + 1;
			if (r_len < 2)
				goto out;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		} else if (!strncmp(pos, "exec.envp[\"", 11)) {
			if (strcmp(pos + strlen(pos) - 2, "\"]"))
				goto out;
			pos = eq + 1;
			if (!strcmp(pos, "NULL"))
				goto next;
			if (r_len < 2)
				goto out;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		}
		for (left = 0; left < AKARI_MAX_CONDITION_KEYWORD; left++) {
			const char *keyword = akari_condition_keyword[left];
			if (strcmp(pos, keyword))
				continue;
			break;
		}
		if (left == AKARI_MAX_CONDITION_KEYWORD) {
			if (!akari_parse_ulong(&left_min, &pos))
				goto out;
			if (pos[0] == '-') {
				pos++;
				if (!akari_parse_ulong(&left_max, &pos) || pos[0] ||
				    left_min > left_max)
					goto out;
			} else if (pos[0])
				goto out;
		}
		pos = eq + 1;
		if (left == AKARI_EXEC_REALPATH || left == AKARI_SYMLINK_TARGET) {
			if (r_len < 2)
				goto out;
			if (pos[0] == '@')
				goto next;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		}
		for (right = 0; right < AKARI_MAX_CONDITION_KEYWORD; right++) {
			const char *keyword = akari_condition_keyword[right];
			if (strcmp(pos, keyword))
				continue;
			break;
		}
		if (right < AKARI_MAX_CONDITION_KEYWORD)
			goto next;
		if (pos[0] == '@' && pos[1])
			goto next;
		if (!akari_parse_ulong(&right_min, &pos))
			goto out;
		if (pos[0] == '-') {
			pos++;
			if (!akari_parse_ulong(&right_max, &pos) || pos[0] ||
			    right_min > right_max)
				goto out;
		} else if (pos[0])
			goto out;
next:
		pos = next;
	}
	return true;
out:
	printf("%u: ERROR: '%s' is an illegal condition.\n", akari_line, pos);
	akari_errors++;
	return false;
}

static void akari_check_capability_policy(char *data)
{
	static const char *capability_keywords[] = {
		"use_route", "use_packet", "SYS_REBOOT", "SYS_VHANGUP",
		"SYS_TIME", "SYS_NICE", "SYS_SETHOSTNAME", "use_kernel_module",
		"SYS_KEXEC_LOAD", "SYS_PTRACE", NULL
	};
	int i;
	for (i = 0; capability_keywords[i]; i++) {
		if (!strcmp(data, capability_keywords[i]))
			return;
	}
	printf("%u: ERROR: '%s' is a bad capability name.\n", akari_line, data);
	akari_errors++;
}

static void akari_check_signal_policy(char *data)
{
	int sig;
	char *cp;
	cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
	*cp++ = '\0';
	if (sscanf(data, "%d", &sig) != 1) {
		printf("%u: ERROR: '%s' is a bad signal number.\n", akari_line, data);
		akari_errors++;
	}
	if (!akari_correct_domain(cp)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n", akari_line, cp);
		akari_errors++;
	}
}

static void akari_check_env_policy(char *data)
{
	if (!akari_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad vakarible name.\n", akari_line, data);
		akari_errors++;
	}
}

static void akari_check_inet_network_policy(char *data)
{
	u16 min_address[8];
	u16 max_address[8];
	unsigned int min_port;
	unsigned int max_port;
	int count;
	static const char *types[3] = { "stream ", "dgram ", "raw " };
	static const char *ops[6] = { "bind ", "connect ", "listen ",
				      "accept ", "send ", "recv " };
	int i;
	for (i = 0; i < 3; i++)
		if (akari_str_starts(data, types[i]))
			break;
	if (i == 3)
		goto out;
	for (i = 0; i < 6; i++)
		if (akari_str_starts(data, ops[i]))
			break;
	if (i == 6)
		goto out;
	count = sscanf(data, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-"
		       "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8 || count == 16)
		goto next;
	count = sscanf(data, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4 || count == 8)
		goto next;
	if (*data != '@') /* Don't reject address_group. */
		goto out;
 next:
	data = strchr(data, ' ');
	if (!data)
		goto out;
	count = sscanf(data, "%u-%u", &min_port, &max_port);
	if (count == 1 || count == 2) {
		if (count == 1)
			max_port = min_port;
		if (min_port <= max_port && max_port < 65536)
			return;
	}
out:
	printf("%u: ERROR: Bad network address.\n", akari_line);
	akari_errors++;
}

static void akari_check_unix_network_policy(char *data)
{
	static const char *types[3] = { "stream ", "dgram ", "seqpaket " };
	static const char *ops[6] = { "bind ", "connect ", "listen ",
				      "accept ", "send ", "recv " };
	int i;
	for (i = 0; i < 3; i++)
		if (akari_str_starts(data, types[i]))
			break;
	if (i == 3)
		goto out;
	for (i = 0; i < 6; i++)
		if (akari_str_starts(data, ops[i]))
			break;
	if (i == 6)
		goto out;
	if (*data == '@' || akari_correct_path(data))
		/* Don't reject path_group. */
		return;
out:
	printf("%u: ERROR: Bad network address.\n", akari_line);
	akari_errors++;
}

static void akari_check_file_policy(char *data)
{
	static const struct {
		const char * const keyword;
		const int paths;
	} acl_type_array[] = {
		{ "append",     1 },
		{ "chgrp",      2 },
		{ "chmod",      2 },
		{ "chown",      2 },
		{ "chroot",     1 },
		{ "create",     2 },
		{ "execute",    1 },
		{ "ioctl",      2 },
		{ "link",       2 },
		{ "mkblock",    4 },
		{ "mkchar",     4 },
		{ "mkdir",      2 },
		{ "mkfifo",     2 },
		{ "mksock",     2 },
		{ "mount",      4 },
		{ "pivot_root", 2 },
		{ "read",       1 },
		{ "rename",     2 },
		{ "rmdir",      1 },
		{ "symlink",    1 },
		{ "transit",    1 },
		{ "truncate",   1 },
		{ "unlink",     1 },
		{ "unmount",    1 },
		{ "write",      1 },
		{ NULL, 0 }
	};
	char *filename = strchr(data, ' ');
	char *cp;
	int type;
	if (!filename) {
		printf("%u: ERROR: Unknown command '%s'\n", akari_line, data);
		akari_errors++;
		return;
	}
	*filename++ = '\0';
	for (type = 0; acl_type_array[type].keyword; type++) {
		if (strcmp(data, acl_type_array[type].keyword))
			continue;
		if (acl_type_array[type].paths == 4) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       akari_line);
				break;
			}
			if (!akari_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument\n",
				       akari_line, cp + 1);
				break;
			}
			*cp = '\0';
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       akari_line);
				break;
			}
			if (!akari_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       akari_line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (acl_type_array[type].paths >= 2) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       akari_line);
				break;
			}
			if (!akari_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       akari_line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (!akari_correct_word(filename)) {
			printf("%u: ERROR: '%s' is a bad argument.\n", akari_line,
			       filename);
			break;
		}
		return;
	}
	if (!acl_type_array[type].keyword)
		printf("%u: ERROR: Invalid permission '%s %s'\n", akari_line, data,
		       filename);
	akari_errors++;
}

static void akari_check_reserved_port_policy(char *data)
{
	unsigned int from;
	unsigned int to;
	if (strchr(data, ' '))
		goto out;
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536)
			return;
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536)
			return;
	} else {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
out:
	printf("%u: ERROR: '%s' is a bad port number.\n", akari_line, data);
	akari_errors++;
}

static void akari_check_domain_transition_policy(char *program)
{
	char *domainname = strstr(program, " from ");
	if (!domainname) {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
	*domainname = '\0';
	domainname += 6;
	if (strcmp(program, "any") && !akari_correct_path(program)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", akari_line,
		       program);
		akari_errors++;
	}
	if (strcmp(domainname, "any") && !akari_correct_path(domainname) &&
	    !akari_correct_domain(domainname)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n",
		       akari_line, domainname);
		akari_errors++;
	}
}

static void akari_check_path_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
	*cp++ = '\0';
	if (!akari_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", akari_line, data);
		akari_errors++;
	}
	if (!akari_correct_word(cp)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", akari_line, cp);
		akari_errors++;
	}
}

static void akari_check_number_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	unsigned long v;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
	*cp++ = '\0';
	if (!akari_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", akari_line, data);
		akari_errors++;
	}
	data = cp;
	cp = strchr(data, '-');
	if (cp)
		*cp = '\0';
	if (!akari_parse_ulong(&v, &data) || *data) {
		printf("%u: ERROR: '%s' is a bad number.\n", akari_line, data);
		akari_errors++;
	}
	if (cp && !akari_parse_ulong(&v, &cp)) {
		printf("%u: ERROR: '%s' is a bad number.\n", akari_line, cp);
		akari_errors++;
	}
}

static void akari_check_address_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	u16 min_address[8];
	u16 max_address[8];
	int count;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", akari_line);
		akari_errors++;
		return;
	}
	*cp++ = '\0';
	if (!akari_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", akari_line, data);
		akari_errors++;
	}
	count = sscanf(cp, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-"
		       "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8 || count == 16)
		return;
	count = sscanf(cp, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4 || count == 8)
		return;
	printf("%u: ERROR: '%s' is a bad address.\n", akari_line, cp);
	akari_errors++;
}

static void akari_check_task_policy(char *data)
{
	if (akari_str_starts(data, "auto_execute_handler ") ||
	    akari_str_starts(data, "denied_execute_handler ")) {
		if (!akari_correct_path(data)) {
			printf("%u: ERROR: '%s' is a bad pathname.\n",
			       akari_line, data);
			akari_errors++;
		}
	} else if (akari_str_starts(data, "auto_domain_transition ") ||
		   akari_str_starts(data, "manual_domain_transition ")) {
		if (!akari_correct_domain(data)) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       akari_line, data);
			akari_errors++;
		}
	}
}

static void akari_check_domain_policy(char *policy)
{
	static int domain = EOF;
	_Bool is_delete = false;
	_Bool is_select = false;
	if (akari_str_starts(policy, "delete "))
		is_delete = true;
	else if (akari_str_starts(policy, "select "))
		is_select = true;
	if (!strncmp(policy, "<kernel>", 8)) {
		if (!akari_correct_domain(policy) ||
		    strlen(policy) >= AKARI_MAX_PATHNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       akari_line, policy);
			akari_errors++;
		} else {
			if (is_delete)
				domain = EOF;
			else
				domain = 0;
		}
	} else if (is_select) {
		printf("%u: ERROR: Command 'select' is valid for selecting "
		       "domains only.\n", akari_line);
		akari_errors++;
	} else if (domain == EOF) {
		printf("%u: WARNING: '%s' is unprocessed because domain is not "
		       "selected.\n", akari_line, policy);
		akari_warnings++;
	} else if (akari_str_starts(policy, "use_profile ")) {
		unsigned int profile;
		if (sscanf(policy, "%u", &profile) != 1 ||
		    profile >= 256) {
			printf("%u: ERROR: '%s' is a bad profile.\n",
			       akari_line, policy);
			akari_errors++;
		}
	} else if (!strcmp(policy, "transition_failed")) {
		/* Nothing to do. */
	} else if (!strcmp(policy, "quota_exceeded")) {
		/* Nothing to do. */
	} else {
		char *cp = akari_find_condition_part(policy);
		if (cp && !akari_check_condition(cp))
			return;
		if (akari_str_starts(policy, "file "))
			akari_check_file_policy(policy);
		else if (akari_str_starts(policy, "network inet "))
			akari_check_inet_network_policy(policy);
		else if (akari_str_starts(policy, "network unix "))
			akari_check_unix_network_policy(policy);
		else if (akari_str_starts(policy, "misc env "))
			akari_check_env_policy(policy);
		else if (akari_str_starts(policy, "capability "))
			akari_check_capability_policy(policy);
		else if (akari_str_starts(policy, "ipc signal "))
			akari_check_signal_policy(policy);
		else if (akari_str_starts(policy, "task "))
			akari_check_task_policy(policy);
		else {
			printf("%u: ERROR: Invalid permission '%s'\n",
			       akari_line, policy);
			akari_errors++;
		}
	}
}

static void akari_check_exception_policy(char *policy)
{
	akari_str_starts(policy, "delete ");
	if (akari_str_starts(policy, "initialize_domain ") ||
	    akari_str_starts(policy, "no_initialize_domain ") ||
	    akari_str_starts(policy, "keep_domain ") ||
	    akari_str_starts(policy, "no_keep_domain ")) {
		akari_check_domain_transition_policy(policy);
	} else if (akari_str_starts(policy, "path_group ")) {
		akari_check_path_group_policy(policy);
	} else if (akari_str_starts(policy, "number_group ")) {
		akari_check_number_group_policy(policy);
	} else if (akari_str_starts(policy, "address_group ")) {
		akari_check_address_group_policy(policy);
	} else if (akari_str_starts(policy, "aggregator ")) {
		char *cp = strchr(policy, ' ');
		if (!cp) {
			printf("%u: ERROR: Too few parameters.\n", akari_line);
			akari_errors++;
		} else {
			*cp++ = '\0';
			if (!akari_correct_word(policy)) {
				printf("%u: ERROR: '%s' is a bad pattern.\n",
				       akari_line, policy);
				akari_errors++;
			}
			if (!akari_correct_path(cp)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       akari_line, cp);
				akari_errors++;
			}
		}
	} else if (akari_str_starts(policy, "file_pattern ")) {
		if (!akari_correct_word(policy)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       akari_line, policy);
			akari_errors++;
		}
	} else if (akari_str_starts(policy, "deny_autobind ")) {
		akari_check_reserved_port_policy(policy);
	} else if (akari_str_starts(policy, "acl_group ")) {
		unsigned int group;
		char *cp = strchr(policy, ' ');
		if (cp && sscanf(policy, "%u", &group) == 1 && group < 256) {
			akari_check_domain_policy(cp + 1);
		} else {
			printf("%u: ERROR: Bad group '%s'.\n", akari_line,
			       policy);
			akari_errors++;
		}
	} else {
		printf("%u: ERROR: Unknown command '%s'.\n", akari_line, policy);
		akari_errors++;
	}
}

int main(int argc, char *argv[])
{
	char *policy = NULL;
	int policy_type = AKARI_POLICY_TYPE_UNKNOWN;
	if (argc > 1) {
		switch (argv[1][0]) {
		case 'e':
			policy_type = AKARI_POLICY_TYPE_EXCEPTION_POLICY;
			break;
		case 'd':
			policy_type = AKARI_POLICY_TYPE_DOMAIN_POLICY;
			break;
		}
	}
	if (policy_type == AKARI_POLICY_TYPE_UNKNOWN) {
		fprintf(stderr, "%s e|d < policy_to_check\n", argv[0]);
		return 0;
	}
	while (true) {
		_Bool badchar_warned = false;
		int pos = 0;
		akari_line++;
		while (true) {
			static int max_policy_len = 0;
			int c = getchar();
			if (c == EOF)
				goto out;
			if (pos == max_policy_len) {
				char *cp;
				max_policy_len += 4096;
				cp = realloc(policy, max_policy_len);
				if (!cp)
					akari_out_of_memory();
				policy = cp;
			}
			policy[pos++] = (char) c;
			if (c == '\n') {
				policy[--pos] = '\0';
				break;
			}
			if (badchar_warned ||
			    c == '\t' || (c >= ' ' && c < 127))
				continue;
			printf("%u: WARNING: Line contains illegal "
			       "character (\\%03o).\n", akari_line, c);
			akari_warnings++;
			badchar_warned = true;
		}
		akari_normalize_line(policy);
		if (!policy[0] || policy[0] == '#')
			continue;
		switch (policy_type) {
		case AKARI_POLICY_TYPE_DOMAIN_POLICY:
			akari_check_domain_policy(policy);
			break;
		case AKARI_POLICY_TYPE_EXCEPTION_POLICY:
			akari_check_exception_policy(policy);
			break;
		}
	}
 out:
	free(policy);
	policy = NULL;
	akari_line--;
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       akari_line, akari_line > 1 ? "s" : "", akari_errors, akari_errors > 1 ? "s" : "",
	       akari_warnings, akari_warnings > 1 ? "s" : "");
	return akari_errors ? 2 : (akari_warnings ? 1 : 0);
}
