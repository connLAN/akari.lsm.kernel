/*
 * security/ccsecurity/util.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3-rc   2011/09/29
 */

#include "internal.h"

/* Lock for protecting policy. */
DEFINE_MUTEX(ccs_policy_lock);

/* Has /sbin/init started? */
bool ccs_policy_loaded;

/* Mapping table from "enum ccs_mac_index" to "enum ccs_mac_category_index". */
const u8 ccs_index2category[CCS_MAX_MAC_INDEX] = {
	/* CONFIG::file group */
	[CCS_MAC_FILE_EXECUTE]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_OPEN]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CREATE]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UNLINK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_GETATTR]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RMDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKFIFO]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKSOCK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_TRUNCATE]   = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_SYMLINK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKBLOCK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKCHAR]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_LINK]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RENAME]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHMOD]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHOWN]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHGRP]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_IOCTL]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHROOT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MOUNT]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UMOUNT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_PIVOT_ROOT] = CCS_MAC_CATEGORY_FILE,
	/* CONFIG::misc group */
	[CCS_MAC_ENVIRON]         = CCS_MAC_CATEGORY_MISC,
	/* CONFIG::network group */
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = CCS_MAC_CATEGORY_NETWORK,
	/* CONFIG::ipc group */
	[CCS_MAC_SIGNAL]          = CCS_MAC_CATEGORY_IPC,
	/* CONFIG::capability group */
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_NICE]          = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_PTRACE]        = CCS_MAC_CATEGORY_CAPABILITY,
};

/**
 * ccs_convert_time - Convert time_t to YYYY/MM/DD hh/mm/ss.
 *
 * @time:  Seconds since 1970/01/01 00:00:00.
 * @stamp: Pointer to "struct ccs_time".
 *
 * Returns nothing.
 *
 * This function does not handle Y2038 problem.
 */
void ccs_convert_time(time_t time, struct ccs_time *stamp)
{
	static const u16 ccs_eom[2][12] = {
		{ 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
		{ 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
	};
	u16 y;
	u8 m;
	bool r;
	stamp->sec = time % 60;
	time /= 60;
	stamp->min = time % 60;
	time /= 60;
	stamp->hour = time % 24;
	time /= 24;
	for (y = 1970; ; y++) {
		const unsigned short days = (y & 3) ? 365 : 366;
		if (time < days)
			break;
		time -= days;
	}
	r = (y & 3) == 0;
	for (m = 0; m < 11 && time >= ccs_eom[r][m]; m++);
	if (m)
		time -= ccs_eom[r][m - 1];
	stamp->year = y;
	stamp->month = ++m;
	stamp->day = ++time;
}

/**
 * ccs_permstr - Find permission keywords.
 *
 * @string: String representation for permissions in foo/bar/buz format.
 * @keyword: Keyword to find from @string/
 *
 * Returns ture if @keyword was found in @string, false otherwise.
 *
 * This function assumes that strncmp(w1, w2, strlen(w1)) != 0 if w1 != w2.
 */
bool ccs_permstr(const char *string, const char *keyword)
{
	const char *cp = strstr(string, keyword);
	if (cp)
		return cp == string || *(cp - 1) == '/';
	return false;
}

/**
 * ccs_read_token - Read a word from a line.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns a word on success, "" otherwise.
 *
 * To allow the caller to skip NULL check, this function returns "" rather than
 * NULL if there is no more words to read.
 */
char *ccs_read_token(struct ccs_acl_param *param)
{
	char *pos = param->data;
	char *del = strchr(pos, ' ');
	if (del)
		*del++ = '\0';
	else
		del = pos + strlen(pos);
	param->data = del;
	return pos;
}

/**
 * ccs_get_domainname - Read a domainname from a line.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns a domainname on success, NULL otherwise.
 */
const struct ccs_path_info *ccs_get_domainname(struct ccs_acl_param *param)
{
	char *start = param->data;
	char *pos = start;
	while (*pos) {
		if (*pos++ != ' ' || *pos++ == '/')
			continue;
		pos -= 2;
		*pos++ = '\0';
		break;
	}
	param->data = pos;
	if (ccs_correct_domain(start))
		return ccs_get_name(start);
	return NULL;
}

/**
 * ccs_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns one of values in "enum ccs_value_type".
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
u8 ccs_parse_ulong(unsigned long *result, char **str)
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
	*result = simple_strtoul(cp, &ep, base);
	if (cp == ep)
		return CCS_VALUE_TYPE_INVALID;
	*str = ep;
	switch (base) {
	case 16:
		return CCS_VALUE_TYPE_HEXADECIMAL;
	case 8:
		return CCS_VALUE_TYPE_OCTAL;
	default:
		return CCS_VALUE_TYPE_DECIMAL;
	}
}

/**
 * ccs_print_ulong - Print an "unsigned long" value.
 *
 * @buffer:     Pointer to buffer.
 * @buffer_len: Size of @buffer.
 * @value:      An "unsigned long" value.
 * @type:       Type of @value.
 *
 * Returns nothing.
 */
void ccs_print_ulong(char *buffer, const int buffer_len,
		     const unsigned long value, const u8 type)
{
	if (type == CCS_VALUE_TYPE_DECIMAL)
		snprintf(buffer, buffer_len, "%lu", value);
	else if (type == CCS_VALUE_TYPE_OCTAL)
		snprintf(buffer, buffer_len, "0%lo", value);
	else
		snprintf(buffer, buffer_len, "0x%lX", value);
}

/**
 * ccs_parse_name_union - Parse a ccs_name_union.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_name_union".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_parse_name_union(struct ccs_acl_param *param,
			  struct ccs_name_union *ptr)
{
	char *filename;
	if (param->data[0] == '@') {
		param->data++;
		ptr->group = ccs_get_group(param, CCS_PATH_GROUP);
		return ptr->group != NULL;
	}
	filename = ccs_read_token(param);
	if (!ccs_correct_word(filename))
		return false;
	ptr->filename = ccs_get_name(filename);
	return ptr->filename != NULL;
}

/**
 * ccs_parse_number_union - Parse a ccs_number_union.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_number_union".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_parse_number_union(struct ccs_acl_param *param,
			    struct ccs_number_union *ptr)
{
	char *data;
	u8 type;
	unsigned long v;
	memset(ptr, 0, sizeof(*ptr));
	if (param->data[0] == '@') {
		param->data++;
		ptr->group = ccs_get_group(param, CCS_NUMBER_GROUP);
		return ptr->group != NULL;
	}
	data = ccs_read_token(param);
	type = ccs_parse_ulong(&v, &data);
	if (type == CCS_VALUE_TYPE_INVALID)
		return false;
	ptr->values[0] = v;
	ptr->value_type[0] = type;
	if (!*data) {
		ptr->values[1] = v;
		ptr->value_type[1] = type;
		return true;
	}
	if (*data++ != '-')
		return false;
	type = ccs_parse_ulong(&v, &data);
	if (type == CCS_VALUE_TYPE_INVALID || *data || ptr->values[0] > v)
		return false;
	ptr->values[1] = v;
	ptr->value_type[1] = type;
	return true;
}

/**
 * ccs_byte_range - Check whether the string is a \ooo style octal value.
 *
 * @str: Pointer to the string.
 *
 * Returns true if @str is a \ooo style octal value, false otherwise.
 */
static bool ccs_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

/**
 * ccs_decimal - Check whether the character is a decimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a decimal character, false otherwise.
 */
static bool ccs_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

/**
 * ccs_hexadecimal - Check whether the character is a hexadecimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a hexadecimal character, false otherwise.
 */
static bool ccs_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

/**
 * ccs_alphabet_char - Check whether the character is an alphabet.
 *
 * @c: The character to check.
 *
 * Returns true if @c is an alphabet character, false otherwise.
 */
static bool ccs_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * ccs_make_byte - Make byte value from three octal characters.
 *
 * @c1: The first character.
 * @c2: The second character.
 * @c3: The third character.
 *
 * Returns byte value.
 */
static u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * ccs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
bool ccs_str_starts(char **src, const char *find)
{
	const int len = strlen(find);
	char *tmp = *src;
	if (strncmp(tmp, find, len))
		return false;
	tmp += len;
	*src = tmp;
	return true;
}

/**
 * ccs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Returns nothing.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
void ccs_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/**
 * ccs_correct_word2 - Check whether the given string follows the naming rules.
 *
 * @string: The byte sequence to check. Not '\0'-terminated.
 * @len:    Length of @string.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool ccs_correct_word2(const char *string, size_t len)
{
	const char *const start = string;
	bool in_repetition = false;
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
				c = ccs_make_byte(c, d, e);
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

/**
 * ccs_correct_word - Check whether the given string follows the naming rules.
 *
 * @string: The string to check.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
bool ccs_correct_word(const char *string)
{
	return ccs_correct_word2(string, strlen(string));
}

/**
 * ccs_correct_path - Check whether the given pathname follows the naming rules.
 *
 * @filename: The pathname to check.
 *
 * Returns true if @filename follows the naming rules, false otherwise.
 */
bool ccs_correct_path(const char *filename)
{
	return *filename == '/' && ccs_correct_word(filename);
}

/**
 * ccs_correct_domain - Check whether the given domainname follows the naming rules.
 *
 * @domainname: The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
bool ccs_correct_domain(const unsigned char *domainname)
{
	if (!domainname || !ccs_domain_def(domainname))
		return false;
	domainname = strchr(domainname, ' ');
	if (!domainname++)
		return true;
	while (1) {
		const unsigned char *cp = strchr(domainname, ' ');
		if (!cp)
			break;
		if (*domainname != '/' ||
		    !ccs_correct_word2(domainname, cp - domainname))
			return false;
		domainname = cp + 1;
	}
	return ccs_correct_path(domainname);
}

/**
 * ccs_domain_def - Check whether the given token can be a domainname.
 *
 * @buffer: The token to check.
 *
 * Returns true if @buffer possibly be a domainname, false otherwise.
 */
bool ccs_domain_def(const unsigned char *buffer)
{
	const unsigned char *cp;
	int len;
	if (*buffer != '<')
		return false;
	cp = strchr(buffer, ' ');
	if (!cp)
		len = strlen(buffer);
	else
		len = cp - buffer;
	if (buffer[len - 1] != '>' || !ccs_correct_word2(buffer + 1, len - 2))
		return false;
	return true;
}

/**
 * ccs_find_domain - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct ccs_domain_info" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_domain_info *ccs_find_domain(const char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	list_for_each_entry_srcu(domain, &ccs_domain_list, list, &ccs_ss) {
		if (!domain->is_deleted &&
		    !ccs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * ccs_const_part_length - Evaluate the initial length without a pattern in a token.
 *
 * @filename: The string to evaluate.
 *
 * Returns the initial length without a pattern in @filename.
 */
static int ccs_const_part_length(const char *filename)
{
	char c;
	int len = 0;
	if (!filename)
		return 0;
	while (1) {
		c = *filename++;
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
	return len;
}

/**
 * ccs_fill_path_info - Fill in "struct ccs_path_info" members.
 *
 * @ptr: Pointer to "struct ccs_path_info" to fill in.
 *
 * The caller sets "struct ccs_path_info"->name.
 */
void ccs_fill_path_info(struct ccs_path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);
	ptr->total_len = len;
	ptr->const_len = ccs_const_part_length(name);
	ptr->is_dir = len && (name[len - 1] == '/');
	ptr->is_patterned = (ptr->const_len < len);
	ptr->hash = full_name_hash(name, len);
}

/**
 * ccs_file_matches_pattern2 - Pattern matching without '/' character and "\-" pattern.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end)
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
				else if (ccs_byte_range(filename + 1))
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
			if (!ccs_decimal(c))
				return false;
			break;
		case 'x':
			if (!ccs_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!ccs_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && ccs_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (ccs_file_matches_pattern2(filename + i,
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
				else if (ccs_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (ccs_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (ccs_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (ccs_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (ccs_file_matches_pattern2(filename + i,
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

/**
 * ccs_file_matches_pattern - Pattern matching without '/' character.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end)
{
	const char *pattern_start = pattern;
	bool first = true;
	bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = ccs_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = ccs_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

/**
 * ccs_path_matches_pattern2 - Do pathname pattern matching.
 *
 * @f: The start of string to check.
 * @p: The start of pattern to compare.
 *
 * Returns true if @f matches @p, false otherwise.
 */
static bool ccs_path_matches_pattern2(const char *f, const char *p)
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
		if (!ccs_file_matches_pattern(f, f_delimiter, p, p_delimiter))
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
		if (!ccs_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (ccs_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}

/**
 * ccs_path_matches_pattern - Check whether the given filename matches the given pattern.
 *
 * @filename: The filename to check.
 * @pattern:  The pattern to compare.
 *
 * Returns true if matches, false otherwise.
 *
 * The following patterns are available.
 *   \\     \ itself.
 *   \ooo   Octal representation of a byte.
 *   \*     Zero or more repetitions of characters other than '/'.
 *   \@     Zero or more repetitions of characters other than '/' or '.'.
 *   \?     1 byte character other than '/'.
 *   \$     One or more repetitions of decimal digits.
 *   \+     1 decimal digit.
 *   \X     One or more repetitions of hexadecimal digits.
 *   \x     1 hexadecimal digit.
 *   \A     One or more repetitions of alphabet characters.
 *   \a     1 alphabet character.
 *
 *   \-     Subtraction operator.
 *
 *   /\{dir\}/   '/' + 'One or more repetitions of dir/' (e.g. /dir/ /dir/dir/
 *               /dir/dir/dir/ ).
 */
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern)
{
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !ccs_pathcmp(filename, pattern);
	/* Don't compare directory and non-directory. */
	if (filename->is_dir != pattern->is_dir)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return ccs_path_matches_pattern2(f, p);
}

/**
 * ccs_get_exe - Get ccs_realpath() of current process.
 *
 * Returns the ccs_realpath() of current process on success, NULL otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function didn't return NULL.
 */
const char *ccs_get_exe(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	const char *cp = NULL;
	if (!mm)
		return NULL;
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
			struct path path = { vma->vm_file->f_vfsmnt,
					     vma->vm_file->f_dentry };
			cp = ccs_realpath_from_path(&path);
#else
			cp = ccs_realpath_from_path(&vma->vm_file->f_path);
#endif
			break;
		}
	}
	up_read(&mm->mmap_sem);
	return cp;
}

/**
 * ccs_get_config - Get config for specified profile's specified functionality.
 *
 * @profile: Profile number.
 * @index:   Index number of functionality.
 *
 * Returns config.
 *
 * First, check for CONFIG::category::functionality.
 * If CONFIG::category::functionality is set to use default, then check
 * CONFIG::category. If CONFIG::category is set to use default, then use
 * CONFIG. CONFIG cannot be set to use default.
 */
u8 ccs_get_config(const u8 profile, const u8 index)
{
	u8 config;
	const struct ccs_profile *p;
	if (!ccs_policy_loaded)
		return CCS_CONFIG_DISABLED;
	p = ccs_profile(profile);
	config = p->config[index];
	if (config == CCS_CONFIG_USE_DEFAULT)
		config = p->config[ccs_index2category[index]
				   + CCS_MAX_MAC_INDEX];
	if (config == CCS_CONFIG_USE_DEFAULT)
		config = p->default_config;
	return config;
}

/**
 * ccs_init_request_info - Initialize "struct ccs_request_info" members.
 *
 * @r:     Pointer to "struct ccs_request_info" to initialize.
 * @index: Index number of functionality.
 *
 * Returns mode.
 *
 * "task auto_domain_transition" keyword is evaluated before returning mode for
 * @index. If "task auto_domain_transition" keyword was specified and
 * transition to that domain failed, the current thread will be killed by
 * SIGKILL. Note that if current->pid == 1, sending SIGKILL won't work.
 */
int ccs_init_request_info(struct ccs_request_info *r, const u8 index)
{
	u8 i;
	const char *buf;
	for (i = 0; i < 255; i++) {
		const u8 profile = ccs_current_domain()->profile;
		memset(r, 0, sizeof(*r));
		r->profile = profile;
		r->type = index;
		r->mode = ccs_get_mode(profile, index);
		r->param_type = CCS_TYPE_AUTO_TASK_ACL;
		ccs_check_acl(r, NULL);
		if (!r->granted)
			return r->mode;
		buf = container_of(r->matched_acl, typeof(struct ccs_task_acl),
				   head)->domainname->name;
		if (!ccs_assign_domain(buf, true))
			break;
	}
	ccs_transition_failed(buf);
	return CCS_CONFIG_DISABLED;
}

/**
 * ccs_domain_quota_ok - Check for domain's quota.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns true if the domain is not exceeded quota, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_domain_quota_ok(struct ccs_request_info *r)
{
	unsigned int count = 0;
	struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	if (r->mode != CCS_CONFIG_LEARNING)
		return false;
	if (!domain)
		return true;
	list_for_each_entry_srcu(ptr, &domain->acl_info_list, list, &ccs_ss) {
		u16 perm;
		u8 i;
		if (ptr->is_deleted)
			continue;
		switch (ptr->type) {
		case CCS_TYPE_PATH_ACL:
			perm = container_of(ptr, struct ccs_path_acl,
					    head)->perm;
			break;
		case CCS_TYPE_PATH2_ACL:
			perm = container_of(ptr, struct ccs_path2_acl,
					    head)->perm;
			break;
		case CCS_TYPE_PATH_NUMBER_ACL:
			perm = container_of(ptr, struct ccs_path_number_acl,
					    head)->perm;
			break;
		case CCS_TYPE_MKDEV_ACL:
			perm = container_of(ptr, struct ccs_mkdev_acl,
					    head)->perm;
			break;
		case CCS_TYPE_INET_ACL:
			perm = container_of(ptr, struct ccs_inet_acl,
					    head)->perm;
			break;
		case CCS_TYPE_UNIX_ACL:
			perm = container_of(ptr, struct ccs_unix_acl,
					    head)->perm;
			break;
		case CCS_TYPE_AUTO_EXECUTE_HANDLER:
		case CCS_TYPE_DENIED_EXECUTE_HANDLER:
		case CCS_TYPE_AUTO_TASK_ACL:
			perm = 0;
			break;
		default:
			perm = 1;
		}
		for (i = 0; i < 16; i++)
			if (perm & (1 << i))
				count++;
	}
	if (count < ccs_profile(r->profile)->pref[CCS_PREF_MAX_LEARNING_ENTRY])
		return true;
	if (!domain->flags[CCS_DIF_QUOTA_WARNED]) {
		domain->flags[CCS_DIF_QUOTA_WARNED] = true;
		/* r->granted = false; */
		ccs_write_log(r, "%s", ccs_dif[CCS_DIF_QUOTA_WARNED]);
		printk(KERN_WARNING "WARNING: "
		       "Domain '%s' has too many ACLs to hold. "
		       "Stopped learning mode.\n", domain->domainname->name);
	}
	return false;
}
