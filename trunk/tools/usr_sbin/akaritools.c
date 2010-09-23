/*
 * akaritools.c
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

struct akari_savename_entry {
	struct akari_savename_entry *next;
	struct akari_path_info entry;
};

struct akari_free_memory_block_list {
	struct akari_free_memory_block_list *next;
	char *ptr;
	int len;
};

#define AKARI_SAVENAME_MAX_HASH            256
#define AKARI_PAGE_SIZE                    4096

_Bool akari_network_mode = false;
u32 akari_network_ip = INADDR_NONE;
u16 akari_network_port = 0;
struct akari_task_entry *akari_task_list = NULL;
int akari_task_list_len = 0;

/* Prototypes */

static _Bool akari_byte_range(const char *str);
static _Bool akari_decimal(const char c);
static _Bool akari_hexadecimal(const char c);
static _Bool akari_alphabet_char(const char c);
static u8 akari_make_byte(const u8 c1, const u8 c2, const u8 c3);
static inline unsigned long akari_partial_name_hash(unsigned long c, unsigned long prevhash);
static inline unsigned int akari_full_name_hash(const unsigned char *name, unsigned int len);
static void *akari_alloc_element(const unsigned int size);
static int akari_const_part_length(const char *filename);
static int akari_domainname_compare(const void *a, const void *b);
static int akari_path_info_compare(const void *a, const void *b);
static void akari_sort_domain_policy(struct akari_domain_policy *dp);

/* Utility functions */

void akari_out_of_memory(void)
{
	fprintf(stderr, "Out of memory. Aborted.\n");
	exit(1);
}

_Bool akari_str_starts(char *str, const char *begin)
{
	const int len = strlen(begin);
	if (strncmp(str, begin, len))
		return false;
	memmove(str, str + len, strlen(str + len) + 1);
	return true;
}

static _Bool akari_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

static _Bool akari_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

static _Bool akari_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

static _Bool akari_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static u8 akari_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

void akari_normalize_line(unsigned char *line)
{
	unsigned char *sp = line;
	unsigned char *dp = line;
	_Bool first = true;
	while (*sp && (*sp <= ' ' || 127 <= *sp))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (' ' < *sp && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || 127 <= *sp))
			sp++;
	}
	*dp = '\0';
}

char *akari_make_filename(const char *prefix, const time_t time)
{
	struct tm *tm = localtime(&time);
	static char filename[1024];
	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename) - 1,
		 "%s.%02d-%02d-%02d.%02d:%02d:%02d.conf",
		 prefix, tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);
	return filename;
}

/* Copied from kernel source. */
static inline unsigned long akari_partial_name_hash(unsigned long c,
						  unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/* Copied from kernel source. */
static inline unsigned int akari_full_name_hash(const unsigned char *name,
					      unsigned int len)
{
	unsigned long hash = 0;
	while (len--)
		hash = akari_partial_name_hash(*name++, hash);
	return (unsigned int) hash;
}

static void *akari_alloc_element(const unsigned int size)
{
	static char *buf = NULL;
	static unsigned int buf_used_len = AKARI_PAGE_SIZE;
	char *ptr = NULL;
	if (size > AKARI_PAGE_SIZE)
		return NULL;
	if (buf_used_len + size > AKARI_PAGE_SIZE) {
		ptr = malloc(AKARI_PAGE_SIZE);
		if (!ptr)
			akari_out_of_memory();
		buf = ptr;
		memset(buf, 0, AKARI_PAGE_SIZE);
		buf_used_len = size;
		ptr = buf;
	} else if (size) {
		int i;
		ptr = buf + buf_used_len;
		buf_used_len += size;
		for (i = 0; i < size; i++)
			if (ptr[i])
				akari_out_of_memory();
	}
	return ptr;
}

static int akari_const_part_length(const char *filename)
{
	int len = 0;
	if (filename) {
		while (true) {
			char c = *filename++;
			if (!c)
				break;
			if (c != '\\') {
				len++;
				continue;
			}
			c = *filename++;
			switch (c) {
			case '\\':  /* "\\" */
				len += 2;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				c = *filename++;
				if (c < '0' || c > '7')
					break;
				c = *filename++;
				if (c < '0' || c > '7')
					break;
				len += 4;
				continue;
			}
			break;
		}
	}
	return len;
}

_Bool akari_domain_def(const unsigned char *domainname)
{
	return !strncmp(domainname, AKARI_ROOT_NAME, AKARI_ROOT_NAME_LEN) &&
		(domainname[AKARI_ROOT_NAME_LEN] == '\0'
		 || domainname[AKARI_ROOT_NAME_LEN] == ' ');
}

void akari_fprintf_encoded(FILE *fp, const char *pathname)
{
	while (true) {
		unsigned char c = *(const unsigned char *) pathname++;
		if (!c)
			break;
		if (c == '\\') {
			fputc('\\', fp);
			fputc('\\', fp);
		} else if (c > ' ' && c < 127) {
			fputc(c, fp);
		} else {
			fprintf(fp, "\\%c%c%c", (c >> 6) + '0',
				((c >> 3) & 7) + '0', (c & 7) + '0');
		}
	}
}

_Bool akari_decode(const char *ascii, char *bin)
{
	while (true) {
		char c = *ascii++;
		*bin++ = c;
		if (!c)
			break;
		if (c == '\\') {
			char d;
			char e;
			u8 f;
			c = *ascii++;
			switch (c) {
			case '\\':      /* "\\" */
				continue;
			case '0':       /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *ascii++;
				if (d < '0' || d > '7')
					break;
				e = *ascii++;
				if (e < '0' || e > '7')
					break;
				f = (u8) ((c - '0') << 6) +
					(((u8) (d - '0')) << 3) +
					(((u8) (e - '0')));
				if (f <= ' ' || f >= 127) {
					*(bin - 1) = f;
					continue;
				}
			}
			return false;
		} else if (c <= ' ' || c >= 127) {
			return false;
		}
	}
	return true;
}

static _Bool akari_correct_word2(const char *string, size_t len)
{
	const char *const start = string;
	_Bool in_repetition = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!len)
		goto out;
	while (len--) {
		c = *string++;
		if (c == '\\') {
			if (!len--)
				goto out;
			c = *string++;
			switch (c) {
			case '\\':  /* "\\" */
				continue;
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				continue;
			case '{':   /* "/\{" */
				if (string - 3 < start || *(string - 3) != '/')
					break;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*string != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if (!len-- || !len--)
					break;
				d = *string++;
				e = *string++;
				if (d < '0' || d > '7' || e < '0' || e > '7')
					break;
				c = akari_make_byte(c, d, e);
				if (c <= ' ' || c >= 127)
					continue;
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (in_repetition)
		goto out;
	return true;
 out:
	return false;
}

_Bool akari_correct_word(const char *string)
{
	return akari_correct_word2(string, strlen(string));
}

_Bool akari_correct_path(const char *filename)
{
	return *filename == '/' && akari_correct_word(filename);
}

_Bool akari_correct_domain(const unsigned char *domainname)
{
	if (!domainname || strncmp(domainname, AKARI_ROOT_NAME,
				   AKARI_ROOT_NAME_LEN))
		goto out;
	domainname += AKARI_ROOT_NAME_LEN;
	if (!*domainname)
		return true;
	if (*domainname++ != ' ')
		goto out;
	while (1) {
		const unsigned char *cp = strchr(domainname, ' ');
		if (!cp)
			break;
		if (*domainname != '/' ||
		    !akari_correct_word2(domainname, cp - domainname - 1))
			goto out;
		domainname = cp + 1;
	}
	return akari_correct_path(domainname);
 out:
	return false;
}

static _Bool akari_file_matches_pattern2(const char *filename,
				       const char *filename_end,
				       const char *pattern, const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		char c;
		if (*pattern != '\\') {
			if (*filename++ != *pattern++)
				return false;
			continue;
		}
		c = *filename;
		pattern++;
		switch (*pattern) {
			int i;
			int j;
		case '?':
			if (c == '/') {
				return false;
			} else if (c == '\\') {
				if (filename[1] == '\\')
					filename++;
				else if (akari_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '\\':
			if (c != '\\')
				return false;
			if (*++filename != '\\')
				return false;
			break;
		case '+':
			if (!akari_decimal(c))
				return false;
			break;
		case 'x':
			if (!akari_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!akari_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && akari_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (akari_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (filename[i + 1] == '\\')
					i++;
				else if (akari_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (akari_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (akari_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (akari_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (akari_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
			}
			return false; /* Not matched or bad pattern. */
		}
		filename++;
		pattern++;
	}
	while (*pattern == '\\' &&
	       (*(pattern + 1) == '*' || *(pattern + 1) == '@'))
		pattern += 2;
	return filename == filename_end && pattern == pattern_end;
}

static _Bool akari_file_matches_pattern(const char *filename,
				      const char *filename_end,
				      const char *pattern, const char *pattern_end)
{
	const char *pattern_start = pattern;
	_Bool first = true;
	_Bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = akari_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = akari_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

static _Bool akari_path_matches_pattern2(const char *f, const char *p)
{
	const char *f_delimiter;
	const char *p_delimiter;
	while (*f && *p) {
		f_delimiter = strchr(f, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		p_delimiter = strchr(p, '/');
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (*p == '\\' && *(p + 1) == '{')
			goto recursive;
		if (!akari_file_matches_pattern(f, f_delimiter, p, p_delimiter))
			return false;
		f = f_delimiter;
		if (*f)
			f++;
		p = p_delimiter;
		if (*p)
			p++;
	}
	/* Ignore trailing "\*" and "\@" in @pattern. */
	while (*p == '\\' &&
	       (*(p + 1) == '*' || *(p + 1) == '@'))
		p += 2;
	return !*f && !*p;
 recursive:
	/*
	 * The "\{" pattern is permitted only after '/' character.
	 * This guarantees that below "*(p - 1)" is safe.
	 * Also, the "\}" pattern is permitted only before '/' character
	 * so that "\{" + "\}" pair will not break the "\-" operator.
	 */
	if (*(p - 1) != '/' || p_delimiter <= p + 3 || *p_delimiter != '/' ||
	    *(p_delimiter - 1) != '}' || *(p_delimiter - 2) != '\\')
		return false; /* Bad pattern. */
	do {
		/* Compare current component with pattern. */
		if (!akari_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (akari_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}

_Bool akari_path_matches_pattern(const struct akari_path_info *filename,
			       const struct akari_path_info *pattern)
{
	/*
	if (!filename || !pattern)
		return false;
	*/
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !akari_pathcmp(filename, pattern);
	/* Don't compare directory and non-directory. */
	if (filename->is_dir != pattern->is_dir)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return akari_path_matches_pattern2(f, p);
}

int akari_string_compare(const void *a, const void *b)
{
	return strcmp(*(char **) a, *(char **) b);
}

_Bool akari_pathcmp(const struct akari_path_info *a, const struct akari_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

void akari_fill_path_info(struct akari_path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);
	ptr->total_len = len;
	ptr->const_len = akari_const_part_length(name);
	ptr->is_dir = len && (name[len - 1] == '/');
	ptr->is_patterned = (ptr->const_len < len);
	ptr->hash = akari_full_name_hash(name, len);
}

static unsigned int akari_memsize(const unsigned int size)
{
	if (size <= 1048576)
		return ((size / AKARI_PAGE_SIZE) + 1) * AKARI_PAGE_SIZE;
	return 0;
}

const struct akari_path_info *akari_savename(const char *name)
{
	static struct akari_free_memory_block_list fmb_list = { NULL, NULL, 0 };
	/* The list of names. */
	static struct akari_savename_entry name_list[AKARI_SAVENAME_MAX_HASH];
	struct akari_savename_entry *ptr;
	struct akari_savename_entry *prev = NULL;
	unsigned int hash;
	struct akari_free_memory_block_list *fmb = &fmb_list;
	int len;
	static _Bool first_call = true;
	if (!name)
		return NULL;
	len = strlen(name) + 1;
	hash = akari_full_name_hash((const unsigned char *) name, len - 1);
	if (first_call) {
		int i;
		first_call = false;
		memset(&name_list, 0, sizeof(name_list));
		for (i = 0; i < AKARI_SAVENAME_MAX_HASH; i++) {
			name_list[i].entry.name = "/";
			akari_fill_path_info(&name_list[i].entry);
		}
	}
	ptr = &name_list[hash % AKARI_SAVENAME_MAX_HASH];
	while (ptr) {
		if (hash == ptr->entry.hash && !strcmp(name, ptr->entry.name))
			goto out;
		prev = ptr;
		ptr = ptr->next;
	}
	while (len > fmb->len) {
		char *cp;
		if (fmb->next) {
			fmb = fmb->next;
			continue;
		}
		cp = malloc(akari_memsize(len));
		if (!cp)
			akari_out_of_memory();
		fmb->next = akari_alloc_element(sizeof(*fmb->next));
		if (!fmb->next)
			akari_out_of_memory();
		memset(cp, 0, akari_memsize(len));
		fmb = fmb->next;
		fmb->ptr = cp;
		fmb->len = akari_memsize(len);
	}
	ptr = akari_alloc_element(sizeof(*ptr));
	if (!ptr)
		akari_out_of_memory();
	memset(ptr, 0, sizeof(struct akari_savename_entry));
	ptr->entry.name = fmb->ptr;
	memmove(fmb->ptr, name, len);
	akari_fill_path_info(&ptr->entry);
	fmb->ptr += len;
	fmb->len -= len;
	prev->next = ptr; /* prev != NULL because name_list is not empty. */
	if (!fmb->len) {
		struct akari_free_memory_block_list *ptr = &fmb_list;
		while (ptr->next != fmb)
			ptr = ptr->next;
		ptr->next = fmb->next;
	}
out:
	return ptr ? &ptr->entry : NULL;
}

int akari_parse_number(const char *number, struct akari_number_entry *entry)
{
	unsigned long min;
	unsigned long max;
	char *cp;
	memset(entry, 0, sizeof(*entry));
	if (number[0] != '0') {
		if (sscanf(number, "%lu", &min) != 1)
			return -EINVAL;
	} else if (number[1] == 'x' || number[1] == 'X') {
		if (sscanf(number + 2, "%lX", &min) != 1)
			return -EINVAL;
	} else if (sscanf(number, "%lo", &min) != 1)
		return -EINVAL;
	cp = strchr(number, '-');
	if (cp)
		number = cp + 1;
	if (number[0] != '0') {
		if (sscanf(number, "%lu", &max) != 1)
			return -EINVAL;
	} else if (number[1] == 'x' || number[1] == 'X') {
		if (sscanf(number + 2, "%lX", &max) != 1)
			return -EINVAL;
	} else if (sscanf(number, "%lo", &max) != 1)
		return -EINVAL;
	entry->min = min;
	entry->max = max;
	return 0;
}

int akari_parse_ip(const char *address, struct akari_ip_address_entry *entry)
{
	unsigned int min[8];
	unsigned int max[8];
	int i;
	int j;
	memset(entry, 0, sizeof(*entry));
	i = sscanf(address, "%u.%u.%u.%u-%u.%u.%u.%u",
		   &min[0], &min[1], &min[2], &min[3],
		   &max[0], &max[1], &max[2], &max[3]);
	if (i == 4)
		for (j = 0; j < 4; j++)
			max[j] = min[j];
	if (i == 4 || i == 8) {
		for (j = 0; j < 4; j++) {
			entry->min[j] = (u8) min[j];
			entry->max[j] = (u8) max[j];
		}
		return 0;
	}
	i = sscanf(address, "%X:%X:%X:%X:%X:%X:%X:%X-%X:%X:%X:%X:%X:%X:%X:%X",
		   &min[0], &min[1], &min[2], &min[3],
		   &min[4], &min[5], &min[6], &min[7],
		   &max[0], &max[1], &max[2], &max[3],
		   &max[4], &max[5], &max[6], &max[7]);
	if (i == 8)
		for (j = 0; j < 8; j++)
			max[j] = min[j];
	if (i == 8 || i == 16) {
		for (j = 0; j < 8; j++) {
			entry->min[j * 2] = (u8) (min[j] >> 8);
			entry->min[j * 2 + 1] = (u8) min[j];
			entry->max[j * 2] = (u8) (max[j] >> 8);
			entry->max[j * 2 + 1] = (u8) max[j];
		}
		entry->is_ipv6 = true;
		return 0;
	}
	return -EINVAL;
}

int akari_open_stream(const char *filename)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	char c;
	int len = strlen(filename) + 1;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = akari_network_ip;
	addr.sin_port = akari_network_port;
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
	    write(fd, filename, len) != len || read(fd, &c, 1) != 1 || c) {
		close(fd);
		return EOF;
	}
	return fd;
}

int akari_find_domain(struct akari_domain_policy *dp, const char *domainname0,
		    const _Bool is_dis, const _Bool is_dd)
{
	int i;
	struct akari_path_info domainname;
	domainname.name = domainname0;
	akari_fill_path_info(&domainname);
	for (i = 0; i < dp->list_len; i++) {
		if (dp->list[i].is_dis == is_dis &&
		    dp->list[i].is_dd == is_dd &&
		    !akari_pathcmp(&domainname, dp->list[i].domainname))
			return i;
	}
	return EOF;
}

int akari_assign_domain(struct akari_domain_policy *dp, const char *domainname,
		      const _Bool is_dis, const _Bool is_dd)
{
	const struct akari_path_info *saved_domainname;
	int index = akari_find_domain(dp, domainname, is_dis, is_dd);
	if (index >= 0)
		goto found;
	if (!akari_correct_domain(domainname)) {
		fprintf(stderr, "Invalid domainname '%s'\n",
			domainname);
		return EOF;
	}
	dp->list = realloc(dp->list, (dp->list_len + 1) *
			   sizeof(struct akari_domain_info));
	if (!dp->list)
		akari_out_of_memory();
	memset(&dp->list[dp->list_len], 0,
	       sizeof(struct akari_domain_info));
	saved_domainname = akari_savename(domainname);
	if (!saved_domainname)
		akari_out_of_memory();
	dp->list[dp->list_len].domainname = saved_domainname;
	dp->list[dp->list_len].is_dis = is_dis;
	dp->list[dp->list_len].is_dd = is_dd;
	index = dp->list_len++;
found:
	return index;
}

static pid_t akari_get_ppid(const pid_t pid)
{
	char buffer[1024];
	FILE *fp;
	pid_t ppid = 1;
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/status", pid);
	fp = fopen(buffer, "r");
	if (fp) {
		while (memset(buffer, 0, sizeof(buffer)),
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			if (sscanf(buffer, "PPid: %u", &ppid) == 1)
				break;
		}
		fclose(fp);
	}
	return ppid;
}

static char *akari_get_name(const pid_t pid)
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

static int akari_dump_index = 0;

static void akari_sort_process_entry(const pid_t pid, const int depth)
{
	int i;
	for (i = 0; i < akari_task_list_len; i++) {
		if (pid != akari_task_list[i].pid)
			continue;
		akari_task_list[i].index = akari_dump_index++;
		akari_task_list[i].depth = depth;
		akari_task_list[i].selected = true;
	}
	for (i = 0; i < akari_task_list_len; i++) {
		if (pid != akari_task_list[i].ppid)
			continue;
		akari_sort_process_entry(akari_task_list[i].pid, depth + 1);
	}
}

static int akari_task_entry_compare(const void *a, const void *b)
{
	const struct akari_task_entry *a0 = (struct akari_task_entry *) a;
	const struct akari_task_entry *b0 = (struct akari_task_entry *) b;
	return a0->index - b0->index;
}

void akari_read_process_list(_Bool show_all)
{
	int i;
	while (akari_task_list_len) {
		akari_task_list_len--;
		free((void *) akari_task_list[akari_task_list_len].name);
		free((void *) akari_task_list[akari_task_list_len].domain);
	}
	akari_dump_index = 0;
	if (akari_network_mode) {
		FILE *fp = akari_open_write(show_all ? "proc:all_process_status" :
					  "proc:process_status");
		if (!fp)
			return;
		akari_get();
		while (true) {
			char *line = akari_freadline(fp);
			unsigned int pid = 0;
			unsigned int ppid = 0;
			int profile = -1;
			char *name;
			char *domain;
			if (!line)
				break;
			sscanf(line, "PID=%u PPID=%u", &pid, &ppid);
			name = strstr(line, "NAME=");
			if (name)
				name = strdup(name + 5);
			if (!name)
				name = strdup("<UNKNOWN>");
			if (!name)
				akari_out_of_memory();
			line = akari_freadline(fp);
			if (!line ||
			    sscanf(line, "%u %u", &pid, &profile) != 2) {
				free(name);
				break;
			}
			domain = strchr(line, '<');
			if (domain)
				domain = strdup(domain);
			if (!domain)
				domain = strdup("<UNKNOWN>");
			if (!domain)
				akari_out_of_memory();
			akari_task_list = realloc(akari_task_list,
						(akari_task_list_len + 1) *
						sizeof(struct akari_task_entry));
			if (!akari_task_list)
				akari_out_of_memory();
			memset(&akari_task_list[akari_task_list_len], 0,
			       sizeof(akari_task_list[0]));
			akari_task_list[akari_task_list_len].pid = pid;
			akari_task_list[akari_task_list_len].ppid = ppid;
			akari_task_list[akari_task_list_len].profile = profile;
			akari_task_list[akari_task_list_len].name = name;
			akari_task_list[akari_task_list_len].domain = domain;
			akari_task_list_len++;
		}
		akari_put();
		fclose(fp);
	} else {
		static const int line_len = 8192;
		char *line;
		int status_fd = open(AKARI_PROC_POLICY_PROCESS_STATUS, O_RDWR);
		DIR *dir = opendir("/proc/");
		if (status_fd == EOF || !dir) {
			if (status_fd != EOF)
				close(status_fd);
			if (dir)
				closedir(dir);
			return;
		}
		line = malloc(line_len);
		if (!line)
			akari_out_of_memory();
		while (1) {
			char *name;
			char *domain;
			int profile = -1;
			unsigned int pid = 0;
			char buffer[128];
			char test[16];
			struct dirent *dent = readdir(dir);
			if (!dent)
				break;
			if (dent->d_type != DT_DIR ||
			    sscanf(dent->d_name, "%u", &pid) != 1 || !pid)
				continue;
			memset(buffer, 0, sizeof(buffer));
			if (!show_all) {
				snprintf(buffer, sizeof(buffer) - 1,
					 "/proc/%u/exe", pid);
				if (readlink(buffer, test, sizeof(test)) <= 0)
					continue;
			}
			name = akari_get_name(pid);
			if (!name)
				name = strdup("<UNKNOWN>");
			if (!name)
				akari_out_of_memory();
			snprintf(buffer, sizeof(buffer) - 1, "%u\n", pid);
			write(status_fd, buffer, strlen(buffer));
			memset(line, 0, line_len);
			read(status_fd, line, line_len - 1);
			if (sscanf(line, "%u %u", &pid, &profile) != 2) {
				free(name);
				continue;
			}
			domain = strchr(line, '<');
			if (domain)
				domain = strdup(domain);
			if (!domain)
				domain = strdup("<UNKNOWN>");
			if (!domain)
				akari_out_of_memory();
			akari_task_list = realloc(akari_task_list, (akari_task_list_len + 1) *
						sizeof(struct akari_task_entry));
			if (!akari_task_list)
				akari_out_of_memory();
			memset(&akari_task_list[akari_task_list_len], 0,
			       sizeof(akari_task_list[0]));
			akari_task_list[akari_task_list_len].pid = pid;
			akari_task_list[akari_task_list_len].ppid = akari_get_ppid(pid);
			akari_task_list[akari_task_list_len].profile = profile;
			akari_task_list[akari_task_list_len].name = name;
			akari_task_list[akari_task_list_len].domain = domain;
			akari_task_list_len++;
		}
		free(line);
		closedir(dir);
		close(status_fd);
	}
	akari_sort_process_entry(1, 0);
	for (i = 0; i < akari_task_list_len; i++) {
		if (akari_task_list[i].selected) {
			akari_task_list[i].selected = false;
			continue;
		}
		akari_task_list[i].index = akari_dump_index++;
		akari_task_list[i].depth = 0;
	}
	qsort(akari_task_list, akari_task_list_len, sizeof(struct akari_task_entry),
	      akari_task_entry_compare);
}

FILE *akari_open_write(const char *filename)
{
	if (akari_network_mode) {
		const int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in addr;
		FILE *fp;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = akari_network_ip;
		addr.sin_port = akari_network_port;
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
			close(fd);
			return NULL;
		}
		fp = fdopen(fd, "r+");
		/* setbuf(fp, NULL); */
		fprintf(fp, "%s", filename);
		fputc(0, fp);
		fflush(fp);
		if (fgetc(fp) != 0) {
			fclose(fp);
			return NULL;
		}
		return fp;
	} else {
		return fdopen(open(filename, O_WRONLY), "w");
	}
}

FILE *akari_open_read(const char *filename)
{
	if (akari_network_mode) {
		FILE *fp = akari_open_write(filename);
		if (fp) {
			fputc(0, fp);
			fflush(fp);
		}
		return fp;
	} else {
		return fopen(filename, "r");
	}
}

_Bool akari_move_proc_to_file(const char *src, const char *dest)
{
	FILE *proc_fp;
	FILE *file_fp = stdout;
	proc_fp = akari_open_read(src);
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s\n", src);
		return false;
	}
	if (dest) {
		file_fp = fopen(dest, "w");
		if (!file_fp) {
			fprintf(stderr, "Can't open %s\n", dest);
			fclose(proc_fp);
			return false;
		}
	}
	while (true) {
		int c = fgetc(proc_fp);
		if (akari_network_mode && !c)
			break;
		if (c == EOF)
			break;
		fputc(c, file_fp);
	}
	fclose(proc_fp);
	if (file_fp != stdout)
		fclose(file_fp);
	return true;
}

_Bool akari_identical_file(const char *file1, const char *file2)
{
	char buffer1[4096];
	char buffer2[4096];
	struct stat sb1;
	struct stat sb2;
	const int fd1 = open(file1, O_RDONLY);
	const int fd2 = open(file2, O_RDONLY);
	int len1;
	int len2;
	/* Don't compare if file1 is a symlink to file2. */
	if (fstat(fd1, &sb1) || fstat(fd2, &sb2) || sb1.st_ino == sb2.st_ino)
		goto out;
	do {
		len1 = read(fd1, buffer1, sizeof(buffer1));
		len2 = read(fd2, buffer2, sizeof(buffer2));
		if (len1 < 0 || len1 != len2)
			goto out;
		if (memcmp(buffer1, buffer2, len1))
			goto out;
	} while (len1);
	close(fd1);
	close(fd2);
	return true;
out:
	close(fd1);
	close(fd2);
	return false;
}

void akari_clear_domain_policy(struct akari_domain_policy *dp)
{
	int index;
	for (index = 0; index < dp->list_len; index++) {
		free(dp->list[index].string_ptr);
		dp->list[index].string_ptr = NULL;
		dp->list[index].string_count = 0;
	}
	free(dp->list);
	dp->list = NULL;
	dp->list_len = 0;
}

int akari_find_domain_by_ptr(struct akari_domain_policy *dp,
			   const struct akari_path_info *domainname)
{
	int i;
	for (i = 0; i < dp->list_len; i++) {
		if (dp->list[i].domainname == domainname)
			return i;
	}
	return EOF;
}

const char *akari_domain_name(const struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].domainname->name;
}

static int akari_domainname_compare(const void *a, const void *b)
{
	return strcmp(((struct akari_domain_info *) a)->domainname->name,
		      ((struct akari_domain_info *) b)->domainname->name);
}

static int akari_path_info_compare(const void *a, const void *b)
{
	const char *a0 = (*(struct akari_path_info **) a)->name;
	const char *b0 = (*(struct akari_path_info **) b)->name;
	return strcmp(a0, b0);
}

static void akari_sort_domain_policy(struct akari_domain_policy *dp)
{
	int i;
	qsort(dp->list, dp->list_len, sizeof(struct akari_domain_info),
	      akari_domainname_compare);
	for (i = 0; i < dp->list_len; i++)
		qsort(dp->list[i].string_ptr, dp->list[i].string_count,
		      sizeof(struct akari_path_info *), akari_path_info_compare);
}

void akari_read_domain_policy(struct akari_domain_policy *dp, const char *filename)
{
	FILE *fp = stdin;
	if (filename) {
		fp = akari_open_read(filename);
		if (!fp) {
			fprintf(stderr, "Can't open %s\n", filename);
			return;
		}
	}
	akari_get();
	akari_handle_domain_policy(dp, fp, true);
	akari_put();
	if (fp != stdin)
		fclose(fp);
	akari_sort_domain_policy(dp);
}

int akari_write_domain_policy(struct akari_domain_policy *dp, const int fd)
{
	int i;
	int j;
	for (i = 0; i < dp->list_len; i++) {
		const struct akari_path_info **string_ptr
			= dp->list[i].string_ptr;
		const int string_count = dp->list[i].string_count;
		write(fd, dp->list[i].domainname->name,
		      dp->list[i].domainname->total_len);
		write(fd, "\n", 1);
		if (dp->list[i].profile_assigned) {
			char buf[128];
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf) - 1, "use_profile %u\n\n",
				 dp->list[i].profile);
			write(fd, buf, strlen(buf));
		} else
			write(fd, "\n", 1);
		for (j = 0; j < string_count; j++) {
			write(fd, string_ptr[j]->name,
			      string_ptr[j]->total_len);
			write(fd, "\n", 1);
		}
		write(fd, "\n", 1);
	}
	return 0;
}

void akari_delete_domain(struct akari_domain_policy *dp, const int index)
{
	if (index >= 0 && index < dp->list_len) {
		int i;
		free(dp->list[index].string_ptr);
		for (i = index; i < dp->list_len - 1; i++)
			dp->list[i] = dp->list[i + 1];
		dp->list_len--;
	}
}

int akari_add_string_entry(struct akari_domain_policy *dp, const char *entry,
			 const int index)
{
	const struct akari_path_info **acl_ptr;
	int acl_count;
	const struct akari_path_info *cp;
	int i;
	if (index < 0 || index >= dp->list_len) {
		fprintf(stderr, "ERROR: domain is out of range.\n");
		return -EINVAL;
	}
	if (!entry || !*entry)
		return -EINVAL;
	cp = akari_savename(entry);
	if (!cp)
		akari_out_of_memory();

	acl_ptr = dp->list[index].string_ptr;
	acl_count = dp->list[index].string_count;

	/* Check for the same entry. */
	for (i = 0; i < acl_count; i++) {
		/* Faster comparison, for they are akari_savename'd. */
		if (cp == acl_ptr[i])
			return 0;
	}

	acl_ptr = realloc(acl_ptr, (acl_count + 1)
			  * sizeof(const struct akari_path_info *));
	if (!acl_ptr)
		akari_out_of_memory();
	acl_ptr[acl_count++] = cp;
	dp->list[index].string_ptr = acl_ptr;
	dp->list[index].string_count = acl_count;
	return 0;
}

int akari_del_string_entry(struct akari_domain_policy *dp, const char *entry,
			 const int index)
{
	const struct akari_path_info **acl_ptr;
	int acl_count;
	const struct akari_path_info *cp;
	int i;
	if (index < 0 || index >= dp->list_len) {
		fprintf(stderr, "ERROR: domain is out of range.\n");
		return -EINVAL;
	}
	if (!entry || !*entry)
		return -EINVAL;
	cp = akari_savename(entry);
	if (!cp)
		akari_out_of_memory();

	acl_ptr = dp->list[index].string_ptr;
	acl_count = dp->list[index].string_count;

	for (i = 0; i < acl_count; i++) {
		/* Faster comparison, for they are akari_savename'd. */
		if (cp != acl_ptr[i])
			continue;
		dp->list[index].string_count--;
		for (; i < acl_count - 1; i++)
			acl_ptr[i] = acl_ptr[i + 1];
		return 0;
	}
	return -ENOENT;
}

void akari_handle_domain_policy(struct akari_domain_policy *dp, FILE *fp, _Bool is_write)
{
	int i;
	int index = EOF;
	if (!is_write)
		goto read_policy;
	while (true) {
		char *line = akari_freadline(fp);
		_Bool is_delete = false;
		_Bool is_select = false;
		unsigned int profile;
		if (!line)
			break;
		if (akari_str_starts(line, "delete "))
			is_delete = true;
		else if (akari_str_starts(line, "select "))
			is_select = true;
		akari_str_starts(line, "domain=");
		if (akari_domain_def(line)) {
			if (is_delete) {
				index = akari_find_domain(dp, line, false, false);
				if (index >= 0)
					akari_delete_domain(dp, index);
				index = EOF;
				continue;
			}
			if (is_select) {
				index = akari_find_domain(dp, line, false, false);
				continue;
			}
			index = akari_assign_domain(dp, line, false, false);
			continue;
		}
		if (index == EOF || !line[0])
			continue;
		if (sscanf(line, "use_profile %u", &profile) == 1) {
			dp->list[index].profile = (u8) profile;
			dp->list[index].profile_assigned = 1;
		} else if (is_delete)
			akari_del_string_entry(dp, line, index);
		else
			akari_add_string_entry(dp, line, index);
	}
	return;
read_policy:
	for (i = 0; i < dp->list_len; i++) {
		int j;
		const struct akari_path_info **string_ptr
			= dp->list[i].string_ptr;
		const int string_count = dp->list[i].string_count;
		fprintf(fp, "%s\n", akari_domain_name(dp, i));
		if (dp->list[i].profile_assigned)
			fprintf(fp, "use_profile %u\n", dp->list[i].profile);
		fprintf(fp, "\n");
		for (j = 0; j < string_count; j++)
			fprintf(fp, "%s\n", string_ptr[j]->name);
		fprintf(fp, "\n");
	}
}

/* Vakaribles */

static _Bool akari_buffer_locked = false;

void akari_get(void)
{
	if (akari_buffer_locked)
		akari_out_of_memory();
	akari_buffer_locked = true;
}

void akari_put(void)
{
	if (!akari_buffer_locked)
		akari_out_of_memory();
	akari_buffer_locked = false;
}

char *akari_shprintf(const char *fmt, ...)
{
	if (!akari_buffer_locked)
		akari_out_of_memory();
	while (true) {
		static char *policy = NULL;
		static int max_policy_len = 0;
		va_list args;
		int len;
		va_start(args, fmt);
		len = vsnprintf(policy, max_policy_len, fmt, args);
		va_end(args);
		if (len < 0)
			akari_out_of_memory();
		if (len >= max_policy_len) {
			char *cp;
			max_policy_len = len + 1;
			cp = realloc(policy, max_policy_len);
			if (!cp)
				akari_out_of_memory();
			policy = cp;
		} else
			return policy;
	}
}

char *akari_freadline(FILE *fp)
{
	static char *policy = NULL;
	int pos = 0;
	if (!akari_buffer_locked)
		akari_out_of_memory();
	while (true) {
		static int max_policy_len = 0;
		const int c = fgetc(fp);
		if (c == EOF)
			return NULL;
		if (akari_network_mode && !c)
			return NULL;
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
	}
	akari_normalize_line(policy);
	return policy;
}

_Bool akari_check_remote_host(void)
{
	int major = 0;
	int minor = 0;
	int rev = 0;
	FILE *fp = akari_open_read("version");
	if (!fp ||
	    fscanf(fp, "%u.%u.%u", &major, &minor, &rev) < 2 ||
	    major != 1 || minor != 8) {
		const u32 ip = ntohl(akari_network_ip);
		fprintf(stderr, "Can't connect to %u.%u.%u.%u:%u\n",
			(u8) (ip >> 24), (u8) (ip >> 16),
			(u8) (ip >> 8), (u8) ip, ntohs(akari_network_port));
		if (fp)
			fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}
