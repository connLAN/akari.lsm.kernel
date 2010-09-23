/*
 * editpolicy_optimizer.c
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
#include "editpolicy.h"

struct akari_address_group_entry {
	const struct akari_path_info *group_name;
	struct akari_ip_address_entry *member_name;
	int member_name_len;
};

struct akari_number_group_entry {
	const struct akari_path_info *group_name;
	struct akari_number_entry *member_name;
	int member_name_len;
};

/* Prototypes */
static int akari_add_address_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct akari_address_group_entry *akari_find_address_group(const char *group_name);
static int akari_add_number_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct akari_number_group_entry *akari_find_number_group(const char *group_name);
static _Bool akari_compare_path(const char *sarg, const char *darg, const u16 directive);
static _Bool akari_compare_number(const char *sarg, const char *darg);
static _Bool akari_compare_address(const char *sarg, const char *darg);

/* Utility functions */

struct akari_path_group_entry *akari_find_path_group(const char *group_name)
{
	int i;
	for (i = 0; i < akari_path_group_list_len; i++) {
		if (!strcmp(group_name, akari_path_group_list[i].group_name->name))
			return &akari_path_group_list[i];
	}
	return NULL;
}

int akari_add_address_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return akari_add_address_group_entry(data, cp, is_delete);
}

static _Bool akari_compare_path(const char *sarg, const char *darg,
			      const u16 directive)
{
	int i;
	struct akari_path_group_entry *group;
	struct akari_path_info s;
	struct akari_path_info d;
	s.name = sarg;
	d.name = darg;
	akari_fill_path_info(&s);
	akari_fill_path_info(&d);
	if (!akari_pathcmp(&s, &d))
		return true;
	if (d.name[0] == '@')
		return false;
	if (s.name[0] != '@')
		/* Pathname component. */
		return akari_path_matches_pattern(&d, &s);
	/* path_group component. */
	group = akari_find_path_group(s.name + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		const struct akari_path_info *member_name;
		member_name = group->member_name[i];
		if (!akari_pathcmp(member_name, &d))
			return true;
		if (akari_path_matches_pattern(&d, member_name))
			return true;
	}
	return false;
}

static _Bool akari_compare_address(const char *sarg, const char *darg)
{
	int i;
	struct akari_ip_address_entry sentry;
	struct akari_ip_address_entry dentry;
	struct akari_address_group_entry *group;
	if (akari_parse_ip(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* IP address component. */
		if (akari_parse_ip(sarg, &sentry))
			return false;
		if (sentry.is_ipv6 != dentry.is_ipv6 ||
		    memcmp(dentry.min, sentry.min, 16) < 0 ||
		    memcmp(sentry.max, dentry.max, 16) < 0)
			return false;
		return true;
	}
	/* IP address group component. */
	group = akari_find_address_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct akari_ip_address_entry *sentry = &group->member_name[i];
		if (sentry->is_ipv6 == dentry.is_ipv6
		    && memcmp(sentry->min, dentry.min, 16) <= 0
		    && memcmp(dentry.max, sentry->max, 16) <= 0)
			return true;
	}
	return false;
}

static char *akari_tokenize(char *buffer, char *w[], size_t size)
{
	int count = size / sizeof(char *);
	int i;
	char *cp;
	cp = strstr(buffer, " if ");
	if (!cp)
		cp = strstr(buffer, " ; set ");
	if (cp)
		*cp++ = '\0';
	else
		cp = "";
	for (i = 0; i < count; i++)
		w[i] = "";
	for (i = 0; i < count; i++) {
		char *cp = strchr(buffer, ' ');
		if (cp)
			*cp = '\0';
		w[i] = buffer;
		if (!cp)
			break;
		buffer = cp + 1;
	}
	return i < count || !*buffer ? cp : NULL;
}

int akari_add_number_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return akari_add_number_group_entry(data, cp, is_delete);
}

static _Bool akari_compare_number(const char *sarg, const char *darg)
{
	int i;
	struct akari_number_entry sentry;
	struct akari_number_entry dentry;
	struct akari_number_group_entry *group;
	if (akari_parse_number(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* Number component. */
		if (akari_parse_number(sarg, &sentry))
			return false;
		if (sentry.min > dentry.min || sentry.max < dentry.max)
			return false;
		return true;
	}
	/* Number group component. */
	group = akari_find_number_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct akari_number_entry *entry = &group->member_name[i];
		if (entry->min > dentry.min || entry->max < dentry.max)
			continue;
		return true;
	}
	return false;
}

void akari_editpolicy_try_optimize(struct akari_domain_policy *dp, const int current,
				 const int screen)
{
	char *cp;
	u16 s_index;
	int index;
	char *s_cond;
	char *d_cond;
	char *s[5];
	char *d[5];
	if (current < 0)
		return;
	s_index = akari_generic_acl_list[current].directive;
	if (s_index == AKARI_DIRECTIVE_NONE)
		return;
	cp = strdup(akari_generic_acl_list[current].operand);
	if (!cp)
		return;

	s_cond = akari_tokenize(cp, s, sizeof(s));
	if (!s_cond) {
		free(cp);
		return;
	}

	akari_get();
	for (index = 0; index < akari_list_item_count[screen]; index++) {
		char *line;
		const u16 d_index = akari_generic_acl_list[index].directive;
		if (index == current)
			continue;
		if (akari_generic_acl_list[index].selected)
			continue;
		else if (s_index == d_index) {
			/* Source and dest start with same directive. */
		} else {
			/* Source and dest start with different directive. */
			continue;
		}
		line = akari_shprintf("%s", akari_generic_acl_list[index].operand);
		d_cond = akari_tokenize(line, d, sizeof(d));

		/* Compare condition part. */
		if (!d_cond || strcmp(s_cond, d_cond))
			continue;

		/* Compare non condition word. */
		if (0) {
			FILE *fp = fopen("/tmp/log", "a+");
			int i;
			for (i = 0; i < 5; i++) {
				fprintf(fp, "s[%d]='%s'\n", i, s[i]);
				fprintf(fp, "d[%d]='%s'\n", i, d[i]);
			}
			fclose(fp);
		}
		switch (d_index) {
			struct akari_path_info sarg;
			struct akari_path_info darg;
			char c;
			int len;
		case AKARI_DIRECTIVE_FILE_MKBLOCK:
		case AKARI_DIRECTIVE_FILE_MKCHAR:
			if (!akari_compare_number(s[3], d[3]) ||
			    !akari_compare_number(s[2], d[2]))
				continue;
			/* fall through */
		case AKARI_DIRECTIVE_FILE_CREATE:
		case AKARI_DIRECTIVE_FILE_MKDIR:
		case AKARI_DIRECTIVE_FILE_MKFIFO:
		case AKARI_DIRECTIVE_FILE_MKSOCK:
		case AKARI_DIRECTIVE_FILE_IOCTL:
		case AKARI_DIRECTIVE_FILE_CHMOD:
		case AKARI_DIRECTIVE_FILE_CHOWN:
		case AKARI_DIRECTIVE_FILE_CHGRP:
			if (!akari_compare_number(s[1], d[1]))
				continue;
			/* fall through */
		case AKARI_DIRECTIVE_FILE_EXECUTE:
		case AKARI_DIRECTIVE_FILE_READ:
		case AKARI_DIRECTIVE_FILE_WRITE:
		case AKARI_DIRECTIVE_FILE_UNLINK:
		case AKARI_DIRECTIVE_FILE_RMDIR:
		case AKARI_DIRECTIVE_FILE_TRUNCATE:
		case AKARI_DIRECTIVE_FILE_APPEND:
		case AKARI_DIRECTIVE_FILE_UNMOUNT:
		case AKARI_DIRECTIVE_FILE_CHROOT:
		case AKARI_DIRECTIVE_FILE_SYMLINK:
			if (!akari_compare_path(s[0], d[0], d_index))
				continue;
			break;
		case AKARI_DIRECTIVE_FILE_MOUNT:
			if (!akari_compare_number(s[3], d[3]) ||
			    !akari_compare_path(s[2], d[2], d_index))
				continue;
			/* fall through */
		case AKARI_DIRECTIVE_FILE_LINK:
		case AKARI_DIRECTIVE_FILE_RENAME:
		case AKARI_DIRECTIVE_FILE_PIVOT_ROOT:
			if (!akari_compare_path(s[1], d[1], d_index) ||
			    !akari_compare_path(s[0], d[0], d_index))
				continue;
			break;
		case AKARI_DIRECTIVE_IPC_SIGNAL:
			/* Signal number component. */
			if (strcmp(s[0], d[0]))
				continue;
			/* Domainname component. */
			len = strlen(s[1]);
			if (strncmp(s[1], d[1], len))
				continue;
			c = d[1][len];
			if (c && c != ' ')
				continue;
			break;
		case AKARI_DIRECTIVE_NETWORK_INET:
			if (strcmp(s[0], d[0]) || strcmp(s[1], d[1]) ||
			    !akari_compare_address(s[2], d[2]) ||
			    !akari_compare_number(s[3], d[3]))
				continue;
			break;
		case AKARI_DIRECTIVE_MISC_ENV:
			/* An environemnt vakarible name component. */
			sarg.name = s[0];
			akari_fill_path_info(&sarg);
			darg.name = d[0];
			akari_fill_path_info(&darg);
			if (!akari_pathcmp(&sarg, &darg))
				break;
			/* "misc env" doesn't interpret leading @ as
			   path_group. */
			if (darg.is_patterned ||
			    !akari_path_matches_pattern(&darg, &sarg))
				continue;
			break;
		default:
			continue;
		}
		akari_generic_acl_list[index].selected = 1;
	}
	akari_put();
	free(cp);
}

/* Vakaribles */

static struct akari_address_group_entry *akari_address_group_list = NULL;
int akari_address_group_list_len = 0;

/* Main functions */

static int akari_add_address_group_entry(const char *group_name,
				       const char *member_name,
				       const _Bool is_delete)
{
	const struct akari_path_info *saved_group_name;
	int i;
	int j;
	struct akari_ip_address_entry entry;
	struct akari_address_group_entry *group = NULL;
	if (akari_parse_ip(member_name, &entry))
		return -EINVAL;
	if (!akari_correct_word(group_name))
		return -EINVAL;
	saved_group_name = akari_savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < akari_address_group_list_len; i++) {
		group = &akari_address_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (memcmp(&group->member_name[j], &entry,
				   sizeof(entry)))
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j]
					= group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == akari_address_group_list_len) {
		void *vp;
		vp = realloc(akari_address_group_list,
			     (akari_address_group_list_len + 1) *
			     sizeof(struct akari_address_group_entry));
		if (!vp)
			akari_out_of_memory();
		akari_address_group_list = vp;
		group = &akari_address_group_list[akari_address_group_list_len++];
		memset(group, 0, sizeof(struct akari_address_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct akari_ip_address_entry));
	if (!group->member_name)
		akari_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct akari_address_group_entry *akari_find_address_group(const char *group_name)
{
	int i;
	for (i = 0; i < akari_address_group_list_len; i++) {
		if (!strcmp(group_name, akari_address_group_list[i].group_name->name))
			return &akari_address_group_list[i];
	}
	return NULL;
}

static struct akari_number_group_entry *akari_number_group_list = NULL;
int akari_number_group_list_len = 0;

static int akari_add_number_group_entry(const char *group_name,
				      const char *member_name,
				      const _Bool is_delete)
{
	const struct akari_path_info *saved_group_name;
	int i;
	int j;
	struct akari_number_entry entry;
	struct akari_number_group_entry *group = NULL;
	if (akari_parse_number(member_name, &entry))
		return -EINVAL;
	if (!akari_correct_word(group_name))
		return -EINVAL;
	saved_group_name = akari_savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < akari_number_group_list_len; i++) {
		group = &akari_number_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (memcmp(&group->member_name[j], &entry,
				   sizeof(entry)))
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j]
					= group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == akari_number_group_list_len) {
		void *vp;
		vp = realloc(akari_number_group_list,
			     (akari_number_group_list_len + 1) *
			     sizeof(struct akari_number_group_entry));
		if (!vp)
			akari_out_of_memory();
		akari_number_group_list = vp;
		group = &akari_number_group_list[akari_number_group_list_len++];
		memset(group, 0, sizeof(struct akari_number_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct akari_number_entry));
	if (!group->member_name)
		akari_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct akari_number_group_entry *akari_find_number_group(const char *group_name)
{
	int i;
	for (i = 0; i < akari_number_group_list_len; i++) {
		if (!strcmp(group_name, akari_number_group_list[i].group_name->name))
			return &akari_number_group_list[i];
	}
	return NULL;
}
