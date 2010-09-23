/*
 * akaritools.h
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
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <asm/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#define s8 __s8
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define true  1
#define false 0

/***** CONSTANTS DEFINITION START *****/

#define AKARI_ROOT_NAME                    "<kernel>"
#define AKARI_ROOT_NAME_LEN                (sizeof(AKARI_ROOT_NAME) - 1)

#define AKARI_PROC_POLICY_DIR              "/proc/akari/"
#define AKARI_PROC_POLICY_DOMAIN_POLICY    "/proc/akari/domain_policy"
#define AKARI_PROC_POLICY_DOMAIN_STATUS    "/proc/akari/.domain_status"
#define AKARI_PROC_POLICY_EXCEPTION_POLICY "/proc/akari/exception_policy"
#define AKARI_PROC_POLICY_GRANT_LOG        "/proc/akari/grant_log"
#define AKARI_PROC_POLICY_MANAGER          "/proc/akari/manager"
#define AKARI_PROC_POLICY_MEMINFO          "/proc/akari/meminfo"
#define AKARI_PROC_POLICY_PROCESS_STATUS   "/proc/akari/.process_status"
#define AKARI_PROC_POLICY_PROFILE          "/proc/akari/profile"
#define AKARI_PROC_POLICY_QUERY            "/proc/akari/query"
#define AKARI_PROC_POLICY_REJECT_LOG       "/proc/akari/reject_log"

#define AKARI_DISK_POLICY_DIR              "/etc/akari/"
#define AKARI_DISK_POLICY_DOMAIN_POLICY    "domain_policy.conf"
#define AKARI_DISK_POLICY_EXCEPTION_POLICY "exception_policy.conf"
#define AKARI_DISK_POLICY_MANAGER          "manager.conf"
#define AKARI_DISK_POLICY_MEMINFO          "meminfo.conf"
#define AKARI_DISK_POLICY_PROFILE          "profile.conf"

/***** CONSTANTS DEFINITION END *****/

/***** STRUCTURES DEFINITION START *****/

struct akari_path_info {
	const char *name;
	u32 hash;           /* = akari_full_name_hash(name, total_len) */
	u16 total_len;      /* = strlen(name)                        */
	u16 const_len;      /* = akari_const_part_length(name)         */
	_Bool is_dir;       /* = akari_strendswith(name, "/")          */
	_Bool is_patterned; /* = const_len < total_len               */
};

struct akari_ip_address_entry {
	u8 min[16];
	u8 max[16];
	_Bool is_ipv6;
};

struct akari_number_entry {
	unsigned long min;
	unsigned long max;
};

struct akari_domain_info {
	const struct akari_path_info *domainname;
	const struct akari_transition_control_entry *d_t; /* This may be NULL */
	const struct akari_path_info **string_ptr;
	int string_count;
	int number;   /* domain number (-1 if is_dis or is_dd) */
	u8 profile;
	_Bool is_dis; /* domain initializer source */
	_Bool is_dit; /* domain initializer target */
	_Bool is_dk;  /* domain keeper */
	_Bool is_du;  /* unreachable domain */
	_Bool is_dd;  /* deleted domain */
	_Bool profile_assigned;
	u8 group;
};

struct akari_domain_policy {
	struct akari_domain_info *list;
	int list_len;
	unsigned char *list_selected;
};

struct akari_task_entry {
	pid_t pid;
	pid_t ppid;
	char *name;
	char *domain;
	u8 profile;
	_Bool selected;
	int index;
	int depth;
};

/***** STRUCTURES DEFINITION END *****/

/***** PROTOTYPES DEFINITION START *****/

FILE *akari_open_read(const char *filename);
FILE *akari_open_write(const char *filename);
_Bool akari_check_remote_host(void);
_Bool akari_decode(const char *ascii, char *bin);
_Bool akari_correct_domain(const unsigned char *domainname);
_Bool akari_correct_path(const char *filename);
_Bool akari_correct_word(const char *string);
_Bool akari_domain_def(const unsigned char *domainname);
_Bool akari_identical_file(const char *file1, const char *file2);
_Bool akari_move_proc_to_file(const char *src, const char *dest);
_Bool akari_path_matches_pattern(const struct akari_path_info *pathname0, const struct akari_path_info *pattern0);
_Bool akari_pathcmp(const struct akari_path_info *a, const struct akari_path_info *b);
_Bool akari_str_starts(char *str, const char *begin);
char *akari_freadline(FILE *fp);
char *akari_make_filename(const char *prefix, const time_t time);
char *akari_shprintf(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
const char *akari_domain_name(const struct akari_domain_policy *dp, const int index);
const struct akari_path_info *akari_savename(const char *name);
int akari_add_string_entry(struct akari_domain_policy *dp, const char *entry, const int index);
int akari_del_string_entry(struct akari_domain_policy *dp, const char *entry, const int index);
int akari_find_domain(struct akari_domain_policy *dp, const char *domainname0, const _Bool is_dis, const _Bool is_dd);
int akari_find_domain_by_ptr(struct akari_domain_policy *dp, const struct akari_path_info *domainname);
int akari_assign_domain(struct akari_domain_policy *dp, const char *domainname, const _Bool is_dis, const _Bool is_dd);
int akari_open_stream(const char *filename);
int akari_parse_ip(const char *address, struct akari_ip_address_entry *entry);
int akari_parse_number(const char *number, struct akari_number_entry *entry);
int akari_string_compare(const void *a, const void *b);
int akari_write_domain_policy(struct akari_domain_policy *dp, const int fd);
struct akari_path_group_entry *akari_find_path_group(const char *group_name);
u16 akari_find_directive(const _Bool forward, char *line);
void akari_clear_domain_policy(struct akari_domain_policy *dp);
void akari_delete_domain(struct akari_domain_policy *dp, const int index);
void akari_fill_path_info(struct akari_path_info *ptr);
void akari_fprintf_encoded(FILE *fp, const char *akari_pathname);
void akari_get(void);
void akari_handle_domain_policy(struct akari_domain_policy *dp, FILE *fp, _Bool is_write);
void akari_normalize_line(unsigned char *line);
void akari_out_of_memory(void);
void akari_put(void);
void akari_read_domain_policy(struct akari_domain_policy *dp, const char *filename);
void akari_read_process_list(_Bool show_all);

extern _Bool akari_network_mode;
extern u32 akari_network_ip;
extern u16 akari_network_port;
extern struct akari_task_entry *akari_task_list;
extern int akari_task_list_len;

/***** PROTOTYPES DEFINITION END *****/
