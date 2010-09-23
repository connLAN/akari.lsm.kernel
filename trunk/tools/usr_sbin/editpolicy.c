/*
 * editpolicy.c
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
#include "readline.h"

/* Vakaribles */

extern int akari_persistent_fd;

struct akari_path_group_entry *akari_path_group_list = NULL;
int akari_path_group_list_len = 0;
struct akari_generic_acl *akari_generic_acl_list = NULL;
int akari_generic_acl_list_count = 0;

static const char *akari_policy_dir = NULL;
static _Bool akari_offline_mode = false;
static _Bool akari_readonly_mode = false;
static unsigned int akari_refresh_interval = 0;
static _Bool akari_need_reload = false;
static const char *akari_policy_file = NULL;
static const char *akari_list_caption = NULL;
static char *akari_current_domain = NULL;
static unsigned int akari_current_pid = 0;
static int akari_current_screen = AKARI_SCREEN_DOMAIN_LIST;
static struct akari_transition_control_entry *akari_transition_control_list = NULL;
static int akari_transition_control_list_len = 0;
static int akari_profile_sort_type = 0;
static int akari_unnumbered_domain_count = 0;
static int akari_window_width = 0;
static int akari_window_height = 0;
static int akari_current_item_index[AKARI_MAXSCREEN];
int akari_current_y[AKARI_MAXSCREEN];
int akari_list_item_count[AKARI_MAXSCREEN];
static int akari_body_lines = 0;
static int akari_max_eat_col[AKARI_MAXSCREEN];
static int akari_eat_col = 0;
static int akari_max_col = 0;
static int akari_list_indent = 0;
static int akari_acl_sort_type = 0;
static char *akari_last_error = NULL;

/* Prototypes */

static void akari_sigalrm_handler(int sig);
static const char *akari_get_last_name(const struct akari_domain_policy *dp, const int index);
static _Bool akari_keeper_domain(struct akari_domain_policy *dp, const int index);
static _Bool akari_initializer_source(struct akari_domain_policy *dp, const int index);
static _Bool akari_initializer_target(struct akari_domain_policy *dp, const int index);
static _Bool akari_domain_unreachable(struct akari_domain_policy *dp, const int index);
static _Bool akari_deleted_domain(struct akari_domain_policy *dp, const int index);
static const struct akari_transition_control_entry *akari_transition_control(const struct akari_path_info *domainname, const char *program);
static int akari_generic_acl_compare(const void *a, const void *b);
static int akari_generic_acl_compare0(const void *a, const void *b);
static int akari_string_acl_compare(const void *a, const void *b);
static int akari_profile_entry_compare(const void *a, const void *b);
static void akari_read_generic_policy(void);
static int akari_add_transition_control_entry(const char *domainname, const char *program, const u8 type);
static int akari_add_transition_control_policy(char *data, const u8 type);
static int akari_add_path_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static int akari_add_path_group_policy(char *data, const _Bool is_delete);
static void akari_assign_domain_initializer_source(struct akari_domain_policy *dp, const struct akari_path_info *domainname, const char *program);
static int akari_domainname_attribute_compare(const void *a, const void *b);
static void akari_read_domain_and_exception_policy(struct akari_domain_policy *dp);
static void akari_show_current(struct akari_domain_policy *dp);
static const char *akari_eat(const char *str);
static int akari_show_domain_line(struct akari_domain_policy *dp, const int index);
static int akari_show_acl_line(const int index, const int list_indent);
static int akari_show_profile_line(const int index);
static int akari_show_literal_line(const int index);
static int akari_show_meminfo_line(const int index);
static void akari_show_list(struct akari_domain_policy *dp);
static void akari_resize_window(void);
static void akari_up_arrow_key(struct akari_domain_policy *dp);
static void akari_down_arrow_key(struct akari_domain_policy *dp);
static void akari_page_up_key(struct akari_domain_policy *dp);
static void akari_page_down_key(struct akari_domain_policy *dp);
static void akari_adjust_cursor_pos(const int item_count);
static void akari_set_cursor_pos(const int index);
static int akari_count(const unsigned char *array, const int len);
static int akari_count2(const struct akari_generic_acl *array, int len);
static _Bool akari_select_item(struct akari_domain_policy *dp, const int index);
static int akari_generic_acl_compare(const void *a, const void *b);
static void akari_delete_entry(struct akari_domain_policy *dp, const int index);
static void akari_add_entry(struct akari_readline_data *rl);
static void akari_find_entry(struct akari_domain_policy *dp, _Bool input, _Bool forward, const int current, struct akari_readline_data *rl);
static void akari_set_profile(struct akari_domain_policy *dp, const int current);
static void akari_set_level(struct akari_domain_policy *dp, const int current);
static void akari_set_quota(struct akari_domain_policy *dp, const int current);
static int akari_select_window(struct akari_domain_policy *dp, const int current);
static _Bool akari_show_command_key(const int screen, const _Bool readonly);
static int akari_generic_list_loop(struct akari_domain_policy *dp);
static void akari_copy_file(const char *source, const char *dest);
static FILE *akari_editpolicy_open_write(const char *filename);

/* Utility Functions */

static void akari_copy_file(const char *source, const char *dest)
{
	FILE *fp_in = fopen(source, "r");
	FILE *fp_out = fp_in ? akari_editpolicy_open_write(dest) : NULL;
	while (fp_in && fp_out) {
		int c = fgetc(fp_in);
		if (c == EOF)
			break;
		fputc(c, fp_out);
	}
	if (fp_out)
		fclose(fp_out);
	if (fp_in)
		fclose(fp_in);
}

static const char *akari_get_last_name(const struct akari_domain_policy *dp,
				     const int index)
{
	const char *cp0 = akari_domain_name(dp, index);
	const char *cp1 = strrchr(cp0, ' ');
	if (cp1)
		return cp1 + 1;
	return cp0;
}

static int akari_count(const unsigned char *array, const int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i])
			c++;
	return c;
}

static int akari_count2(const struct akari_generic_acl *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

static int akari_count3(const struct akari_task_entry *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

static _Bool akari_keeper_domain(struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].is_dk;
}

static _Bool akari_initializer_source(struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].is_dis;
}

static _Bool akari_initializer_target(struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].is_dit;
}

static _Bool akari_domain_unreachable(struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].is_du;
}

static _Bool akari_deleted_domain(struct akari_domain_policy *dp, const int index)
{
	return dp->list[index].is_dd;
}

static int akari_generic_acl_compare0(const void *a, const void *b)
{
	const struct akari_generic_acl *a0 = (struct akari_generic_acl *) a;
	const struct akari_generic_acl *b0 = (struct akari_generic_acl *) b;
	const char *a1 = akari_directives[a0->directive].alias;
	const char *b1 = akari_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	const int ret = strcmp(a1, b1);
	if (ret)
		return ret;
	return strcmp(a2, b2);
}

static int akari_string_acl_compare(const void *a, const void *b)
{
	const struct akari_generic_acl *a0 = (struct akari_generic_acl *) a;
	const struct akari_generic_acl *b0 = (struct akari_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

static int akari_add_transition_control_policy(char *data, const u8 type)
{
	char *domainname = strstr(data, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == AKARI_TRANSITION_CONTROL_NO_KEEP ||
		   type == AKARI_TRANSITION_CONTROL_KEEP) {
		domainname = data;
		data = NULL;
	}
	return akari_add_transition_control_entry(domainname, data, type);
}

static int akari_add_path_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return akari_add_path_group_entry(data, cp, is_delete);
}

static void akari_assign_domain_initializer_source(struct akari_domain_policy *dp,
						 const struct akari_path_info *domainname,
						 const char *program)
{
	const struct akari_transition_control_entry *d_t =
		akari_transition_control(domainname, program);
	if (d_t && d_t->type == AKARI_TRANSITION_CONTROL_INITIALIZE) {
		char *line;
		akari_get();
		line = akari_shprintf("%s %s", domainname->name, program);
		akari_normalize_line(line);
		if (akari_assign_domain(dp, line, true, false) == EOF)
			akari_out_of_memory();
		akari_put();
	}
}

static int akari_domainname_attribute_compare(const void *a, const void *b)
{
	const struct akari_domain_info *a0 = a;
	const struct akari_domain_info *b0 = b;
	const int k = strcmp(a0->domainname->name, b0->domainname->name);
	if ((k > 0) || (!k && !a0->is_dis && b0->is_dis))
		return 1;
	return k;
}

static const char *akari_transition_type[AKARI_MAX_TRANSITION_TYPE] = {
	[AKARI_TRANSITION_CONTROL_INITIALIZE] = "initialize_domain ",
	[AKARI_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[AKARI_TRANSITION_CONTROL_KEEP] = "keep_domain ",
	[AKARI_TRANSITION_CONTROL_NO_KEEP] = "no_keep_domain ",
};

static int akari_show_domain_line(struct akari_domain_policy *dp, const int index)
{
	int tmp_col = 0;
	const struct akari_transition_control_entry *transition_control;
	char *line;
	const char *sp;
	const int number = dp->list[index].number;
	int redirect_index;
	if (number >= 0) {
		printw("%c%4d:", dp->list_selected[index] ? '&' : ' ', number);
		if (dp->list[index].profile_assigned)
			printw("%3u", dp->list[index].profile);
		else
			printw("???");
		printw(" %c%c%c ", akari_keeper_domain(dp, index) ? '#' : ' ',
		       akari_initializer_target(dp, index) ? '*' : ' ',
		       akari_domain_unreachable(dp, index) ? '!' : ' ');
	} else
		printw("              ");
	tmp_col += 14;
	sp = akari_domain_name(dp, index);
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", akari_eat("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (akari_deleted_domain(dp, index)) {
		printw("%s", akari_eat("( "));
		tmp_col += 2;
	}
	printw("%s", akari_eat(sp));
	tmp_col += strlen(sp);
	if (akari_deleted_domain(dp, index)) {
		printw("%s", akari_eat(" )"));
		tmp_col += 2;
	}
	transition_control = dp->list[index].d_t;
	if (!transition_control)
		goto no_transition_control;
	akari_get();
	line = akari_shprintf(" ( %s%s from %s )",
			    akari_transition_type[transition_control->type],
			    transition_control->program ?
			    transition_control->program->name : "any",
			    transition_control->domainname ?
			    transition_control->domainname->name : "any");
	printw("%s", akari_eat(line));
	tmp_col += strlen(line);
	akari_put();
	goto done;
no_transition_control:
	if (!akari_initializer_source(dp, index))
		goto done;
	akari_get();
	line = akari_shprintf(AKARI_ROOT_NAME "%s", strrchr(akari_domain_name(dp, index), ' '));
	redirect_index = akari_find_domain(dp, line, false, false);
	if (redirect_index >= 0)
		line = akari_shprintf(" ( -> %d )", dp->list[redirect_index].number);
	else
		line = akari_shprintf(" ( -> Not Found )");
	printw("%s", akari_eat(line));
	tmp_col += strlen(line);
	akari_put();
done:
	return tmp_col;
}

static int akari_show_acl_line(const int index, const int list_indent)
{
	u16 directive = akari_generic_acl_list[index].directive;
	const char *cp1 = akari_directives[directive].alias;
	const char *cp2 = akari_generic_acl_list[index].operand;
	int len = list_indent - akari_directives[directive].alias_len;
	printw("%c%4d: %s ",
	       akari_generic_acl_list[index].selected ? '&' : ' ',
	       index, akari_eat(cp1));
	while (len-- > 0)
		printw("%s", akari_eat(" "));
	printw("%s", akari_eat(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

static int akari_show_profile_line(const int index)
{
	const char *cp = akari_generic_acl_list[index].operand;
	const u16 profile = akari_generic_acl_list[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", akari_generic_acl_list[index].selected ? '&' : ' ',
	       index, akari_eat(number));
	printw("%s ", akari_eat(cp));
	return strlen(number) + strlen(cp) + 8;
}

static int akari_show_literal_line(const int index)
{
	const char *cp = akari_generic_acl_list[index].operand;
	printw("%c%4d: %s ",
	       akari_generic_acl_list[index].selected ? '&' : ' ',
	       index, akari_eat(cp));
	return strlen(cp) + 8;
}

static int akari_show_meminfo_line(const int index)
{
	char *line;
	unsigned int now = 0;
	unsigned int quota = -1;
	const char *data = akari_generic_acl_list[index].operand;
	akari_get();
	if (sscanf(data, "Policy: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory used for policy      = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Audit logs: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory used for audit logs  = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Query lists: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory used for query lists = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Total: %u", &now) == 1)
		line = akari_shprintf("Total memory in use         = %10u bytes",
				    now);
	else if (sscanf(data, "Shared: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory for string data      = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else if (sscanf(data, "Private: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory for numeric data     = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else if (sscanf(data, "Dynamic: %u (Quota: %u)", &now, &quota) >= 1)
		line = akari_shprintf("Memory for temporary data   = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else
		line = akari_shprintf("%s", data);
	if (line[0])
		printw("%s", akari_eat(line));
	now = strlen(line);
	akari_put();
	return now;
}

static int akari_domain_sort_type = 0;

static _Bool akari_show_command_key(const int screen, const _Bool readonly)
{
	int c;
	clear();
	printw("Commands available for this screen are:\n\n");
	printw("Q/q        Quit this editor.\n");
	printw("R/r        Refresh to the latest information.\n");
	switch (screen) {
	case AKARI_SCREEN_MEMINFO_LIST:
		break;
	default:
		printw("F/f        Find first.\n");
		printw("N/n        Find next.\n");
		printw("P/p        Find previous.\n");
	}
	printw("W/w        Switch to selected screen.\n");
	/* printw("Tab        Switch to next screen.\n"); */
	switch (screen) {
	case AKARI_SCREEN_MEMINFO_LIST:
		break;
	default:
		printw("Insert     Copy an entry at the cursor position to "
		       "history buffer.\n");
		printw("Space      Invert selection state of an entry at "
		       "the cursor position.\n");
		printw("C/c        Copy selection state of an entry at "
		       "the cursor position to all entries below the cursor "
		       "position.\n");
	}
	switch (screen) {
	case AKARI_SCREEN_DOMAIN_LIST:
		if (akari_domain_sort_type) {
			printw("S/s        Set profile number of selected "
			       "processes.\n");
			printw("Enter      Edit ACLs of a process at the "
			       "cursor position.\n");
		} else {
			if (!readonly) {
				printw("A/a        Add a new domain.\n");
				printw("D/d        Delete selected domains.\n");
				printw("S/s        Set profile number of "
				       "selected domains.\n");
			}
			printw("Enter      Edit ACLs of a domain at the "
			       "cursor position.\n");
		}
		break;
	case AKARI_SCREEN_MEMINFO_LIST:
		if (!readonly)
			printw("S/s        Set memory quota of selected "
			       "items.\n");
		break;
	case AKARI_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("S/s        Set mode of selected items.\n");
		break;
	}
	switch (screen) {
	case AKARI_SCREEN_EXCEPTION_LIST:
	case AKARI_SCREEN_ACL_LIST:
	case AKARI_SCREEN_MANAGER_LIST:
		if (!readonly) {
			printw("A/a        Add a new entry.\n");
			printw("D/d        Delete selected entries.\n");
		}
	}
	switch (screen) {
	case AKARI_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("A/a        Define a new profile.\n");
	}
	switch (screen) {
	case AKARI_SCREEN_ACL_LIST:
		printw("O/o        Set selection state to other entries "
		       "included in an entry at the cursor position.\n");
		/* Fall through. */
	case AKARI_SCREEN_PROFILE_LIST:
		printw("@          Switch sort type.\n");
		break;
	case AKARI_SCREEN_DOMAIN_LIST:
		if (!akari_offline_mode)
			printw("@          Switch domain/process list.\n");
	}
	printw("Arrow-keys and PageUp/PageDown/Home/End keys "
	       "for scroll.\n\n");
	printw("Press '?' to escape from this help.\n");
	refresh();
	while (true) {
		c = akari_getch2();
		if (c == '?' || c == EOF)
			break;
		if (c == 'Q' || c == 'q')
			return false;
	}
	return true;
}

/* Main Functions */

static void akari_close_write(FILE *fp)
{
	if (akari_network_mode) {
		fputc(0, fp);
		fflush(fp);
		fgetc(fp);
	}
	fclose(fp);
}

static void akari_set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		akari_last_error = realloc(akari_last_error, len);
		if (!akari_last_error)
			akari_out_of_memory();
		memset(akari_last_error, 0, len);
		snprintf(akari_last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(akari_last_error);
		akari_last_error = NULL;
	}
}

static FILE *akari_editpolicy_open_write(const char *filename)
{
	if (akari_network_mode) {
		FILE *fp = akari_open_write(filename);
		if (!fp)
			akari_set_error(filename);
		return fp;
	} else if (akari_offline_mode) {
		char request[1024];
		int fd[2];
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
			fprintf(stderr, "socketpair()\n");
			exit(1);
		}
		if (shutdown(fd[0], SHUT_RD))
			goto out;
		memset(request, 0, sizeof(request));
		snprintf(request, sizeof(request) - 1, "POST %s", filename);
		akari_send_fd(request, &fd[1]);
		return fdopen(fd[0], "w");
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		FILE *fp;
		if (akari_readonly_mode)
			return NULL;
		fp = akari_open_write(filename);
		if (!fp)
			akari_set_error(filename);
		return fp;
	}
}

static FILE *akari_editpolicy_open_read(const char *filename)
{
	if (akari_network_mode) {
		return akari_open_read(filename);
	} else if (akari_offline_mode) {
		char request[1024];
		int fd[2];
		FILE *fp;
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
			fprintf(stderr, "socketpair()\n");
			exit(1);
		}
		if (shutdown(fd[0], SHUT_WR))
			goto out;
		fp = fdopen(fd[0], "r");
		if (!fp)
			goto out;
		memset(request, 0, sizeof(request));
		snprintf(request, sizeof(request) - 1, "GET %s", filename);
		akari_send_fd(request, &fd[1]);
		return fp;
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		return fopen(filename, "r");
	}
}

static int akari_open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		akari_set_error(filename);
	return fd;
}

static void akari_sigalrm_handler(int sig)
{
	akari_need_reload = true;
	alarm(akari_refresh_interval);
}

static const char *akari_eat(const char *str)
{
	while (*str && akari_eat_col) {
		str++;
		akari_eat_col--;
	}
	return str;
}

static const struct akari_transition_control_entry *akari_transition_control
(const struct akari_path_info *domainname, const char *program)
{
	int i;
	u8 type;
	struct akari_path_info last_name;
	last_name.name = strrchr(domainname->name, ' ');
	if (last_name.name)
		last_name.name++;
	else
		last_name.name = domainname->name;
	akari_fill_path_info(&last_name);
	for (type = 0; type < AKARI_MAX_TRANSITION_TYPE; type++) {
 next:
		for (i = 0; i < akari_transition_control_list_len; i++) {
			struct akari_transition_control_entry *ptr
				= &akari_transition_control_list[i];
			if (ptr->type != type)
                                continue;
			if (ptr->domainname) {
				if (!ptr->is_last_name) {
					if (akari_pathcmp(ptr->domainname,
							domainname))
						continue;
				} else {
					if (akari_pathcmp(ptr->domainname,
							&last_name))
						continue;
				}
			}
			if (ptr->program && strcmp(ptr->program->name, program))
				continue;
			if (type == AKARI_TRANSITION_CONTROL_NO_INITIALIZE) {
				/*
				 * Do not check for initialize_domain if
				 * no_initialize_domain matched.
				 */
				type = AKARI_TRANSITION_CONTROL_NO_KEEP;
				goto next;
			}
			if (type == AKARI_TRANSITION_CONTROL_INITIALIZE ||
			    type == AKARI_TRANSITION_CONTROL_KEEP)
				return ptr;
			else
				return NULL;
		}
	}
	return NULL;
}

static int akari_profile_entry_compare(const void *a, const void *b)
{
	const struct akari_generic_acl *a0 = (struct akari_generic_acl *) a;
	const struct akari_generic_acl *b0 = (struct akari_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	const int a2 = a0->directive;
	const int b2 = b0->directive;
	if (a2 >= 256 || b2 >= 256) {
		int i;
		static const char *global[5] = {
			"PROFILE_VERSION=",
			"PREFERENCE::audit=",
			"PREFERENCE::learning=",
			"PREFERENCE::permissive=",
			"PREFERENCE::enforcing="
		};
		for (i = 0; i < 5; i++) {
			if (!strncmp(a1, global[i], strlen(global[i])))
				return -1;
			if (!strncmp(b1, global[i], strlen(global[i])))
				return 1;
		}
	}
	if (akari_profile_sort_type == 0) {
		if (a2 == b2)
			return strcmp(a1, b1);
		else
			return a2 - b2;
	} else {
		const int a3 = strcspn(a1, "=");
		const int b3 = strcspn(b1, "=");
		const int c = strncmp(a1, b1, a3 >= b3 ? b3 : a3);
		if (c)
			return c;
		if (a3 != b3)
			return a3 - b3;
		else
			return a2 - b2;
	}
}

static void akari_read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	while (akari_generic_acl_list_count)
		free((void *)
		     akari_generic_acl_list[--akari_generic_acl_list_count].operand);
	if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
		if (akari_network_mode)
			/* We can read after write. */
			fp = akari_editpolicy_open_write(akari_policy_file);
		else if (!akari_offline_mode)
			/* Don't set error message if failed. */
			fp = fopen(akari_policy_file, "r+");
		if (fp) {
			if (akari_domain_sort_type)
				fprintf(fp, "select pid=%u\n", akari_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					akari_current_domain);
			if (akari_network_mode)
				fputc(0, fp);
			fflush(fp);
		}
	}
	if (!fp)
		fp = akari_editpolicy_open_read(akari_policy_file);
	if (!fp) {
		akari_set_error(akari_policy_file);
		return;
	}
	akari_get();
	while (true) {
		char *line = akari_freadline(fp);
		u16 directive;
		char *cp;
		if (!line)
			break;
		if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
			if (akari_domain_def(line)) {
				flag = !strcmp(line, akari_current_domain);
				continue;
			}
			if (!flag || !line[0] ||
			    !strncmp(line, "use_profile ", 12))
				continue;
		} else {
			if (!line[0])
				continue;
		}
		switch (akari_current_screen) {
		case AKARI_SCREEN_EXCEPTION_LIST:
		case AKARI_SCREEN_ACL_LIST:
			directive = akari_find_directive(true, line);
			if (directive == AKARI_DIRECTIVE_NONE)
				continue;
			break;
		case AKARI_SCREEN_PROFILE_LIST:
			cp = strchr(line, '-');
			if (cp) {
				*cp++ = '\0';
				directive = atoi(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				directive = (u16) -1;
			break;
		default:
			directive = AKARI_DIRECTIVE_NONE;
			break;
		}
		akari_generic_acl_list = realloc(akari_generic_acl_list,
					       (akari_generic_acl_list_count + 1) *
					       sizeof(struct akari_generic_acl));
		if (!akari_generic_acl_list)
			akari_out_of_memory();
		cp = strdup(line);
		if (!cp)
			akari_out_of_memory();
		akari_generic_acl_list[akari_generic_acl_list_count].directive = directive;
		akari_generic_acl_list[akari_generic_acl_list_count].selected = 0;
		akari_generic_acl_list[akari_generic_acl_list_count++].operand = cp;
	}
	akari_put();
	fclose(fp);
	switch (akari_current_screen) {
	case AKARI_SCREEN_ACL_LIST:
		qsort(akari_generic_acl_list, akari_generic_acl_list_count,
		      sizeof(struct akari_generic_acl), akari_generic_acl_compare);
		break;
	case AKARI_SCREEN_EXCEPTION_LIST:
		qsort(akari_generic_acl_list, akari_generic_acl_list_count,
		      sizeof(struct akari_generic_acl), akari_generic_acl_compare0);
		break;
	case AKARI_SCREEN_PROFILE_LIST:
		qsort(akari_generic_acl_list, akari_generic_acl_list_count,
		      sizeof(struct akari_generic_acl), akari_profile_entry_compare);
		break;
	default:
		qsort(akari_generic_acl_list, akari_generic_acl_list_count,
		      sizeof(struct akari_generic_acl), akari_string_acl_compare);
	}
}

static int akari_add_transition_control_entry(const char *domainname,
					    const char *program,
					    const u8 type)
{
	void *vp;
	struct akari_transition_control_entry *ptr;
	_Bool is_last_name = false;
	if (program && strcmp(program, "any")) {
		if (!akari_correct_path(program))
			return -EINVAL;
	}
	if (domainname && strcmp(domainname, "any")) {
		if (!akari_correct_domain(domainname)) {
			if (!akari_correct_path(domainname))
				return -EINVAL;
			is_last_name = true;
		}
	}
	vp = realloc(akari_transition_control_list,
		     (akari_transition_control_list_len + 1) *
		     sizeof(struct akari_transition_control_entry));
	if (!vp)
		akari_out_of_memory();
	akari_transition_control_list = vp;
	ptr = &akari_transition_control_list[akari_transition_control_list_len++];
	memset(ptr, 0, sizeof(struct akari_transition_control_entry));
	if (program && strcmp(program, "any")) {
		ptr->program = akari_savename(program);
		if (!ptr->program)
			akari_out_of_memory();
	}
	if (domainname && strcmp(domainname, "any")) {
		ptr->domainname = akari_savename(domainname);
		if (!ptr->domainname)
			akari_out_of_memory();
	}
	ptr->type = type;
	ptr->is_last_name = is_last_name;
	return 0;
}

static int akari_add_path_group_entry(const char *group_name, const char *member_name,
				const _Bool is_delete)
{
	const struct akari_path_info *saved_group_name;
	const struct akari_path_info *saved_member_name;
	int i;
	int j;
	struct akari_path_group_entry *group = NULL;
	if (!akari_correct_word(group_name) || !akari_correct_word(member_name))
		return -EINVAL;
	saved_group_name = akari_savename(group_name);
	saved_member_name = akari_savename(member_name);
	if (!saved_group_name || !saved_member_name)
		return -ENOMEM;
	for (i = 0; i < akari_path_group_list_len; i++) {
		group = &akari_path_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (group->member_name[j] != saved_member_name)
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j] =
					group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == akari_path_group_list_len) {
		akari_path_group_list = realloc(akari_path_group_list,
					  (akari_path_group_list_len + 1) *
					  sizeof(struct akari_path_group_entry));
		if (!akari_path_group_list)
			akari_out_of_memory();
		group = &akari_path_group_list[akari_path_group_list_len++];
		memset(group, 0, sizeof(struct akari_path_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1)
				     * sizeof(const struct akari_path_info *));
	if (!group->member_name)
		akari_out_of_memory();
	group->member_name[group->member_name_len++] = saved_member_name;
	return 0;
}

static _Bool akari_has_execute(char *line)
{
	char *cp = strchr(line, ' ');
	if (!cp)
		return false;
	*cp++ = '\0';
	if (strstr(line, "execute")) {
		memmove(line, cp, strlen(cp) + 1);
		return true;
	}
	return false;
}

static void akari_read_domain_and_exception_policy(struct akari_domain_policy *dp)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	akari_clear_domain_policy(dp);
	akari_transition_control_list_len = 0;
	while (akari_path_group_list_len)
		free(akari_path_group_list[--akari_path_group_list_len].member_name);
	/*
	while (akari_address_group_list_len)
		free(akari_address_group_list[--akari_address_group_list_len].member_name);
	*/
	akari_address_group_list_len = 0;
	akari_number_group_list_len = 0;
	akari_assign_domain(dp, AKARI_ROOT_NAME, false, false);

	/* Load all domain list. */
	fp = NULL;
	if (akari_network_mode)
		/* We can read after write. */
		fp = akari_editpolicy_open_write(akari_policy_file);
	else if (!akari_offline_mode)
		/* Don't set error message if failed. */
		fp = fopen(akari_policy_file, "r+");
	if (fp) {
		fprintf(fp, "select execute\n");
		if (akari_network_mode)
			fputc(0, fp);
		fflush(fp);
	}
	if (!fp)
		fp = akari_editpolicy_open_read(AKARI_PROC_POLICY_DOMAIN_POLICY);
	if (!fp) {
		akari_set_error(AKARI_PROC_POLICY_DOMAIN_POLICY);
		goto no_domain;
	}
	index = EOF;
	akari_get();
	while (true) {
		char *line = akari_freadline(fp);
		unsigned int profile;
		if (!line)
			break;
		if (akari_domain_def(line)) {
			index = akari_assign_domain(dp, line, false, false);
			continue;
		} else if (index == EOF) {
			continue;
		}
		if (akari_str_starts(line, "task auto_execute_handler ") ||
		    akari_str_starts(line, "task denied_execute_handler ") ||
		    (akari_str_starts(line, "file ") && akari_has_execute(line))) {
			char *cp = strchr(line, ' ');
			if (cp)
				*cp = '\0';
			if (*line == '@' || akari_correct_path(line))
				akari_add_string_entry(dp, line, index);
		} else if (sscanf(line, "use_profile %u", &profile) == 1) {
			dp->list[index].profile = (u8) profile;
			dp->list[index].profile_assigned = 1;
		} else if (sscanf(line, "use_group %u", &profile) == 1) {
			dp->list[index].group = (u8) profile;
		}
	}
	akari_put();
	fclose(fp);
no_domain:

	max_index = dp->list_len;

	/* Load domain_initializer list, domain_keeper list. */
	fp = akari_editpolicy_open_read(AKARI_PROC_POLICY_EXCEPTION_POLICY);
	if (!fp) {
		akari_set_error(AKARI_PROC_POLICY_EXCEPTION_POLICY);
		goto no_exception;
	}
	akari_get();
	while (true) {
		unsigned int group;
		char *line = akari_freadline(fp);
		if (!line)
			break;
		if (akari_str_starts(line, "initialize_domain "))
			akari_add_transition_control_policy(line, AKARI_TRANSITION_CONTROL_INITIALIZE);
		else if (akari_str_starts(line, "no_initialize_domain "))
			akari_add_transition_control_policy(line, AKARI_TRANSITION_CONTROL_NO_INITIALIZE);
		else if (akari_str_starts(line, "keep_domain "))
			akari_add_transition_control_policy(line, AKARI_TRANSITION_CONTROL_KEEP);
		else if (akari_str_starts(line, "no_keep_domain "))
			akari_add_transition_control_policy(line, AKARI_TRANSITION_CONTROL_NO_KEEP);
		else if (akari_str_starts(line, "path_group "))
			akari_add_path_group_policy(line, false);
		else if (akari_str_starts(line, "address_group "))
			akari_add_address_group_policy(line, false);
		else if (akari_str_starts(line, "number_group "))
			akari_add_number_group_policy(line, false);
		else if (sscanf(line, "acl_group %u", &group) == 1
			 && group < 256) {
			char *cp = strchr(line + 10, ' ');
			if (cp)
				line = cp + 1;
			if (akari_str_starts(line,
					   "task auto_execute_handler ") ||
			    akari_str_starts(line,
					   "task denied_execute_handler ") ||
			    (akari_str_starts(line, "file ") &&
			     akari_has_execute(line))) {
				cp = strchr(line, ' ');
				if (cp)
					*cp = '\0';
				if (*line == '@' || akari_correct_path(line)) {
					for (index = 0; index < max_index;
					     index++)
						if (dp->list[index].group
						    == group)
							akari_add_string_entry(dp, line, index);
				}
			}
		}
	}
	akari_put();
	fclose(fp);
no_exception:

	/* Find unreachable domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		akari_get();
		line = akari_shprintf("%s", akari_domain_name(dp, index));
		while (true) {
			const struct akari_transition_control_entry *d_t;
			struct akari_path_info parent;
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp++ = '\0';
			parent.name = line;
			akari_fill_path_info(&parent);
			d_t = akari_transition_control(&parent, cp);
			if (!d_t)
				continue;
			/* Initializer under <kernel> is reachable. */
			if (d_t->type == AKARI_TRANSITION_CONTROL_INITIALIZE &&
			    parent.total_len == AKARI_ROOT_NAME_LEN)
				break;
			dp->list[index].d_t = d_t;
			continue;
		}
		akari_put();
		if (dp->list[index].d_t)
			dp->list[index].is_du = true;
	}

	/* Find domain initializer target domains. */
	for (index = 0; index < max_index; index++) {
		char *cp = strchr(akari_domain_name(dp, index), ' ');
		if (!cp || strchr(cp + 1, ' '))
			continue;
		for (i = 0; i < akari_transition_control_list_len; i++) {
			struct akari_transition_control_entry *ptr
				= &akari_transition_control_list[i];
			if (ptr->type != AKARI_TRANSITION_CONTROL_INITIALIZE)
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp + 1))
				continue;
			dp->list[index].is_dit = true;
		}
	}

	/* Find domain keeper domains. */
	for (index = 0; index < max_index; index++) {
		for (i = 0; i < akari_transition_control_list_len; i++) {
			struct akari_transition_control_entry *ptr
				= &akari_transition_control_list[i];
			char *cp;
			if (ptr->type != AKARI_TRANSITION_CONTROL_KEEP)
				continue;
			if (!ptr->is_last_name) {
				if (ptr->domainname &&
				    akari_pathcmp(ptr->domainname,
						dp->list[index].domainname))
					continue;
				dp->list[index].is_dk = true;
				continue;
			}
			cp = strrchr(dp->list[index].domainname->name,
				     ' ');
			if (!cp || (ptr->domainname->name &&
				    strcmp(ptr->domainname->name, cp + 1)))
				continue;
			dp->list[index].is_dk = true;
		}
	}

	/* Create domain initializer source domains. */
	for (index = 0; index < max_index; index++) {
		const struct akari_path_info *domainname
			= dp->list[index].domainname;
		const struct akari_path_info **string_ptr
			= dp->list[index].string_ptr;
		const int max_count = dp->list[index].string_count;
		/* Don't create source domain under <kernel> because
		   they will become akari_target domains. */
		if (domainname->total_len == AKARI_ROOT_NAME_LEN)
			continue;
		for (i = 0; i < max_count; i++) {
			const struct akari_path_info *cp = string_ptr[i];
			struct akari_path_group_entry *group;
			if (cp->name[0] != '@') {
				akari_assign_domain_initializer_source(dp, domainname,
								     cp->name);
				continue;
			}
			group = akari_find_path_group(cp->name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				cp = group->member_name[j];
				akari_assign_domain_initializer_source(dp, domainname,
								     cp->name);
			}
		}
	}

	/* Create missing parent domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		akari_get();
		line = akari_shprintf("%s", akari_domain_name(dp, index));
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (akari_find_domain(dp, line, false, false) != EOF)
				continue;
			if (akari_assign_domain(dp, line, false, true) == EOF)
				akari_out_of_memory();
		}
		akari_put();
	}

	/* Sort by domain name. */
	qsort(dp->list, dp->list_len, sizeof(struct akari_domain_info),
	      akari_domainname_attribute_compare);

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		akari_unnumbered_domain_count = 0;
		for (index = 0; index < dp->list_len; index++) {
			if (akari_deleted_domain(dp, index) ||
			    akari_initializer_source(dp, index)) {
				dp->list[index].number = -1;
				akari_unnumbered_domain_count++;
			} else {
				dp->list[index].number = number++;
			}
		}
	}

	dp->list_selected = realloc(dp->list_selected, dp->list_len);
	if (dp->list_len && !dp->list_selected)
		akari_out_of_memory();
	memset(dp->list_selected, 0, dp->list_len);
}

static int akari_show_process_line(const int index)
{
	char *line;
	int tmp_col = 0;
	int i;
	printw("%c%4d:%3u ", akari_task_list[index].selected ? '&' : ' ', index,
	       akari_task_list[index].profile);
	tmp_col += 10;
	for (i = 0; i < akari_task_list[index].depth - 1; i++) {
		printw("%s", akari_eat("    "));
		tmp_col += 4;
	}
	akari_get();
	line = akari_shprintf("%s%s (%u) %s", akari_task_list[index].depth ?
			    " +- " : "", akari_task_list[index].name,
			    akari_task_list[index].pid, akari_task_list[index].domain);
	printw("%s", akari_eat(line));
	tmp_col += strlen(line);
	akari_put();
	return tmp_col;
}

static void akari_show_list(struct akari_domain_policy *dp)
{
	const int offset = akari_current_item_index[akari_current_screen];
	int i;
	int tmp_col;
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST)
		akari_list_item_count[AKARI_SCREEN_DOMAIN_LIST] = akari_domain_sort_type ?
			akari_task_list_len : dp->list_len;
	else
		akari_list_item_count[akari_current_screen] = akari_generic_acl_list_count;
	clear();
	move(0, 0);
	if (akari_window_height < AKARI_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	akari_editpolicy_color_change(akari_editpolicy_color_head(akari_current_screen), true);
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		if (akari_domain_sort_type) {
			printw("<<< Process State Viewer >>>"
			       "      %d process%s    '?' for help",
			       akari_task_list_len, akari_task_list_len > 1 ? "es" : "");
		} else {
			int i = akari_list_item_count[AKARI_SCREEN_DOMAIN_LIST]
				- akari_unnumbered_domain_count;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c    '?' for help",
			       i, i > 1 ? 's' : ' ');
		}
	} else {
		int i = akari_list_item_count[akari_current_screen];
		printw("<<< %s >>>"
		       "      %d entr%s    '?' for help", akari_list_caption,
		       i, i > 1 ? "ies" : "y");
	}
	/* add color */
	akari_editpolicy_color_change(akari_editpolicy_color_head(akari_current_screen), false);
	akari_eat_col = akari_max_eat_col[akari_current_screen];
	akari_max_col = 0;
	if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
		char *line;
		akari_get();
		line = akari_shprintf("%s", akari_eat(akari_current_domain));
		akari_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		move(2, 0);
		printw("%s", line);
		akari_editpolicy_attr_change(A_REVERSE, false); /* add color */
		akari_put();
	}
	akari_list_indent = 0;
	switch (akari_current_screen) {
	case AKARI_SCREEN_EXCEPTION_LIST:
	case AKARI_SCREEN_ACL_LIST:
		for (i = 0; i < akari_list_item_count[akari_current_screen]; i++) {
			const u16 directive = akari_generic_acl_list[i].directive;
			const int len = akari_directives[directive].alias_len;
			if (len > akari_list_indent)
				akari_list_indent = len;
		}
		break;
	}
	for (i = 0; i < akari_body_lines; i++) {
		const int index = offset + i;
		akari_eat_col = akari_max_eat_col[akari_current_screen];
		if (index >= akari_list_item_count[akari_current_screen])
			break;
		move(AKARI_HEADER_LINES + i, 0);
		switch (akari_current_screen) {
		case AKARI_SCREEN_DOMAIN_LIST:
			if (!akari_domain_sort_type)
				tmp_col = akari_show_domain_line(dp, index);
			else
				tmp_col = akari_show_process_line(index);
			break;
		case AKARI_SCREEN_EXCEPTION_LIST:
		case AKARI_SCREEN_ACL_LIST:
			tmp_col = akari_show_acl_line(index, akari_list_indent);
			break;
		case AKARI_SCREEN_PROFILE_LIST:
			tmp_col = akari_show_profile_line(index);
			break;
		case AKARI_SCREEN_MEMINFO_LIST:
			tmp_col = akari_show_meminfo_line(index);
			break;
		default:
			tmp_col = akari_show_literal_line(index);
			break;
		}
		clrtoeol();
		tmp_col -= akari_window_width;
		if (tmp_col > akari_max_col)
			akari_max_col = tmp_col;
	}
	akari_show_current(dp);
}

static void akari_resize_window(void)
{
	getmaxyx(stdscr, akari_window_height, akari_window_width);
	akari_body_lines = akari_window_height - AKARI_HEADER_LINES;
	if (akari_body_lines <= akari_current_y[akari_current_screen])
		akari_current_y[akari_current_screen] = akari_body_lines - 1;
	if (akari_current_y[akari_current_screen] < 0)
		akari_current_y[akari_current_screen] = 0;
}

static void akari_up_arrow_key(struct akari_domain_policy *dp)
{
	if (akari_current_y[akari_current_screen] > 0) {
		akari_current_y[akari_current_screen]--;
		akari_show_current(dp);
	} else if (akari_current_item_index[akari_current_screen] > 0) {
		akari_current_item_index[akari_current_screen]--;
		akari_show_list(dp);
	}
}

static void akari_down_arrow_key(struct akari_domain_policy *dp)
{
	if (akari_current_y[akari_current_screen] < akari_body_lines - 1) {
		if (akari_current_item_index[akari_current_screen]
		    + akari_current_y[akari_current_screen]
		    < akari_list_item_count[akari_current_screen] - 1) {
			akari_current_y[akari_current_screen]++;
			akari_show_current(dp);
		}
	} else if (akari_current_item_index[akari_current_screen]
		   + akari_current_y[akari_current_screen]
		   < akari_list_item_count[akari_current_screen] - 1) {
		akari_current_item_index[akari_current_screen]++;
		akari_show_list(dp);
	}
}

static void akari_page_up_key(struct akari_domain_policy *dp)
{
	int p0 = akari_current_item_index[akari_current_screen];
	int p1 = akari_current_y[akari_current_screen];
	_Bool refresh;
	if (p0 + p1 > akari_body_lines) {
		p0 -= akari_body_lines;
		if (p0 < 0)
			p0 = 0;
	} else if (p0 + p1 > 0) {
		p0 = 0;
		p1 = 0;
	} else {
		return;
	}
	refresh = (akari_current_item_index[akari_current_screen] != p0);
	akari_current_item_index[akari_current_screen] = p0;
	akari_current_y[akari_current_screen] = p1;
	if (refresh)
		akari_show_list(dp);
	else
		akari_show_current(dp);
}

static void akari_page_down_key(struct akari_domain_policy *dp)
{
	int akari_count = akari_list_item_count[akari_current_screen] - 1;
	int p0 = akari_current_item_index[akari_current_screen];
	int p1 = akari_current_y[akari_current_screen];
	_Bool refresh;
	if (p0 + p1 + akari_body_lines < akari_count) {
		p0 += akari_body_lines;
	} else if (p0 + p1 < akari_count) {
		while (p0 + p1 < akari_count) {
			if (p1 + 1 < akari_body_lines)
				p1++;
			else
				p0++;
		}
	} else {
		return;
	}
	refresh = (akari_current_item_index[akari_current_screen] != p0);
	akari_current_item_index[akari_current_screen] = p0;
	akari_current_y[akari_current_screen] = p1;
	if (refresh)
		akari_show_list(dp);
	else
		akari_show_current(dp);
}

int akari_editpolicy_get_current(void)
{
	int akari_count = akari_list_item_count[akari_current_screen];
	const int p0 = akari_current_item_index[akari_current_screen];
	const int p1 = akari_current_y[akari_current_screen];
	if (!akari_count)
		return EOF;
	if (p0 + p1 < 0 || p0 + p1 >= akari_count) {
		fprintf(stderr, "ERROR: akari_current_item_index=%d akari_current_y=%d\n",
			p0, p1);
		exit(127);
	}
	return p0 + p1;
}

static void akari_show_current(struct akari_domain_policy *dp)
{
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST && !akari_domain_sort_type) {
		char *line;
		const int index = akari_editpolicy_get_current();
		akari_get();
		akari_eat_col = akari_max_eat_col[akari_current_screen];
		line = akari_shprintf("%s", akari_eat(akari_domain_name(dp, index)));
		if (akari_window_width < strlen(line))
			line[akari_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		akari_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		akari_editpolicy_attr_change(A_REVERSE, false); /* add color */
		akari_put();
	}
	move(AKARI_HEADER_LINES + akari_current_y[akari_current_screen], 0);
	akari_editpolicy_line_draw(akari_current_screen);     /* add color */
	refresh();
}

static void akari_adjust_cursor_pos(const int item_count)
{
	if (item_count == 0) {
		akari_current_item_index[akari_current_screen] = 0;
		akari_current_y[akari_current_screen] = 0;
	} else {
		while (akari_current_item_index[akari_current_screen]
		       + akari_current_y[akari_current_screen] >= item_count) {
			if (akari_current_y[akari_current_screen] > 0)
				akari_current_y[akari_current_screen]--;
			else if (akari_current_item_index[akari_current_screen] > 0)
				akari_current_item_index[akari_current_screen]--;
		}
	}
}

static void akari_set_cursor_pos(const int index)
{
	while (index < akari_current_y[akari_current_screen]
	       + akari_current_item_index[akari_current_screen]) {
		if (akari_current_y[akari_current_screen] > 0)
			akari_current_y[akari_current_screen]--;
		else
			akari_current_item_index[akari_current_screen]--;
	}
	while (index > akari_current_y[akari_current_screen]
	       + akari_current_item_index[akari_current_screen]) {
		if (akari_current_y[akari_current_screen] < akari_body_lines - 1)
			akari_current_y[akari_current_screen]++;
		else
			akari_current_item_index[akari_current_screen]++;
	}
}

static _Bool akari_select_item(struct akari_domain_policy *dp, const int index)
{
	int x;
	int y;
	if (index < 0)
		return false;
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		if (!akari_domain_sort_type) {
			if (akari_deleted_domain(dp, index) ||
			    akari_initializer_source(dp, index))
				return false;
			dp->list_selected[index] ^= 1;
		} else {
			akari_task_list[index].selected ^= 1;
		}
	} else {
		akari_generic_acl_list[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	akari_editpolicy_sttr_save();    /* add color */
	akari_show_list(dp);
	akari_editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

static int akari_generic_acl_compare(const void *a, const void *b)
{
	const struct akari_generic_acl *a0 = (struct akari_generic_acl *) a;
	const struct akari_generic_acl *b0 = (struct akari_generic_acl *) b;
	const char *a1 = akari_directives[a0->directive].alias;
	const char *b1 = akari_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	if (akari_acl_sort_type == 0) {
		const int ret = strcmp(a1, b1);
		if (ret)
			return ret;
		return strcmp(a2, b2);
	} else {
		const int ret = strcmp(a2, b2);
		if (ret)
			return ret;
		return strcmp(a1, b1);
	}
}

static void akari_delete_entry(struct akari_domain_policy *dp, const int index)
{
	int c;
	move(1, 0);
	akari_editpolicy_color_change(AKARI_DISP_ERR, true);	/* add color */
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		c = akari_count(dp->list_selected, dp->list_len);
		if (!c && index < dp->list_len)
			c = akari_select_item(dp, index);
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = akari_count2(akari_generic_acl_list, akari_generic_acl_list_count);
		if (!c)
			c = akari_select_item(dp, index);
		if (!c)
			printw("Select entry using Space key first.");
		else
			printw("Delete selected entr%s? ('Y'es/'N'o)",
			       c > 1 ? "ies" : "y");
	}
	akari_editpolicy_color_change(AKARI_DISP_ERR, false);	/* add color */
	clrtoeol();
	refresh();
	if (!c)
		return;
	do {
		c = akari_getch2();
	} while (!(c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == EOF));
	akari_resize_window();
	if (c != 'Y' && c != 'y') {
		akari_show_list(dp);
		return;
	}
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = akari_editpolicy_open_write(AKARI_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 1; i < dp->list_len; i++) {
			if (!dp->list_selected[i])
				continue;
			fprintf(fp, "delete %s\n", akari_domain_name(dp, i));
		}
		akari_close_write(fp);
	} else {
		int i;
		FILE *fp = akari_editpolicy_open_write(akari_policy_file);
		if (!fp)
			return;
		if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
			if (akari_domain_sort_type)
				fprintf(fp, "select pid=%u\n", akari_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					akari_current_domain);
		}
		for (i = 0; i < akari_generic_acl_list_count; i++) {
			u16 directive;
			if (!akari_generic_acl_list[i].selected)
				continue;
			directive = akari_generic_acl_list[i].directive;
			fprintf(fp, "delete %s %s\n",
				akari_directives[directive].original,
				akari_generic_acl_list[i].operand);
		}
		akari_close_write(fp);
	}
}

static void akari_add_entry(struct akari_readline_data *rl)
{
	FILE *fp;
	char *line;
	akari_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = akari_readline(akari_window_height - 1, 0, "Enter new entry> ",
			    rl->history, rl->count, 128000, 8);
	akari_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = akari_add_history(line, rl->history, rl->count, rl->max);
	fp = akari_editpolicy_open_write(akari_policy_file);
	if (!fp)
		goto out;
	switch (akari_current_screen) {
		u16 directive;
	case AKARI_SCREEN_DOMAIN_LIST:
		if (!akari_correct_domain(line)) {
			const int len = strlen(line) + 128;
			akari_last_error = realloc(akari_last_error, len);
			if (!akari_last_error)
				akari_out_of_memory();
			memset(akari_last_error, 0, len);
			snprintf(akari_last_error, len - 1,
				 "%s is an invalid domainname.", line);
			line[0] = '\0';
		}
		break;
	case AKARI_SCREEN_ACL_LIST:
		if (akari_domain_sort_type)
			fprintf(fp, "select pid=%u\n", akari_current_pid);
		else
			fprintf(fp, "select domain=%s\n", akari_current_domain);
		/* Fall through. */
	case AKARI_SCREEN_EXCEPTION_LIST:
		directive = akari_find_directive(false, line);
		if (directive != AKARI_DIRECTIVE_NONE)
			fprintf(fp, "%s ",
				akari_directives[directive].original);
		break;
	case AKARI_SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s-COMMENT=\n", line);
		break;
	}
	fprintf(fp, "%s\n", line);
	akari_close_write(fp);
out:
	free(line);
}

static void akari_find_entry(struct akari_domain_policy *dp, _Bool input, _Bool forward,
			   const int current, struct akari_readline_data *rl)
{
	int index = current;
	char *line = NULL;
	if (current == EOF)
		return;
	if (!input)
		goto start_search;
	akari_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = akari_readline(akari_window_height - 1, 0, "Search> ",
			    rl->history, rl->count, 128000, 8);
	akari_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = akari_add_history(line, rl->history, rl->count, rl->max);
	free(rl->search_buffer[akari_current_screen]);
	rl->search_buffer[akari_current_screen] = line;
	line = NULL;
	index = -1;
start_search:
	akari_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= akari_list_item_count[akari_current_screen])
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
			if (akari_domain_sort_type)
				cp = akari_task_list[index].name;
			else
				cp = akari_get_last_name(dp, index);
		} else if (akari_current_screen == AKARI_SCREEN_PROFILE_LIST) {
			cp = akari_shprintf("%u-%s",
					  akari_generic_acl_list[index].directive,
					  akari_generic_acl_list[index].operand);
		} else {
			const u16 directive = akari_generic_acl_list[index].directive;
			cp = akari_shprintf("%s %s", akari_directives[directive].alias,
					  akari_generic_acl_list[index].operand);
		}
		if (!strstr(cp, rl->search_buffer[akari_current_screen]))
			continue;
		akari_set_cursor_pos(index);
		break;
	}
	akari_put();
out:
	free(line);
	akari_show_list(dp);
}

static void akari_set_profile(struct akari_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!akari_domain_sort_type) {
		if (!akari_count(dp->list_selected, dp->list_len) &&
		    !akari_select_item(dp, current)) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!akari_count3(akari_task_list, akari_task_list_len) &&
		    !akari_select_item(dp, current)) {
			move(1, 0);
			printw("Select processes using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	}
	akari_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = akari_readline(akari_window_height - 1, 0, "Enter profile number> ",
			    NULL, 0, 8, 1);
	akari_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = akari_editpolicy_open_write(AKARI_PROC_POLICY_DOMAIN_POLICY);
	if (!fp)
		goto out;
	if (!akari_domain_sort_type) {
		for (index = 0; index < dp->list_len; index++) {
			if (!dp->list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\n" "use_profile %s\n",
				akari_domain_name(dp, index), line);
		}
	} else {
		for (index = 0; index < akari_task_list_len; index++) {
			if (!akari_task_list[index].selected)
				continue;
			fprintf(fp, "select pid=%u\n" "use_profile %s\n",
				akari_task_list[index].pid, line);
		}
	}
	akari_close_write(fp);
out:
	free(line);
}

static void akari_set_level(struct akari_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!akari_count2(akari_generic_acl_list, akari_generic_acl_list_count))
		akari_select_item(dp, current);
	akari_editpolicy_attr_change(A_BOLD, true);  /* add color */
	akari_initial_readline_data = NULL;
	for (index = 0; index < akari_generic_acl_list_count; index++) {
		char *cp;
		if (!akari_generic_acl_list[index].selected)
			continue;
		cp = strchr(akari_generic_acl_list[index].operand, '=');
		if (!cp)
			continue;
		akari_initial_readline_data = cp + 1;
		break;
	}
	line = akari_readline(akari_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 128000, 1);
	akari_initial_readline_data = NULL;
	akari_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = akari_editpolicy_open_write(AKARI_PROC_POLICY_PROFILE);
	if (!fp)
		goto out;
	for (index = 0; index < akari_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		u16 directive;
		if (!akari_generic_acl_list[index].selected)
			continue;
		akari_get();
		buf = akari_shprintf("%s", akari_generic_acl_list[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = akari_generic_acl_list[index].directive;
		if (directive < 256)
			fprintf(fp, "%u-", directive);
		fprintf(fp, "%s=%s\n", buf, line);
		akari_put();
	}
	akari_close_write(fp);
out:
	free(line);
}

static void akari_set_quota(struct akari_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!akari_count2(akari_generic_acl_list, akari_generic_acl_list_count))
		akari_select_item(dp, current);
	akari_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = akari_readline(akari_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 20, 1);
	akari_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = akari_editpolicy_open_write(AKARI_PROC_POLICY_MEMINFO);
	if (!fp)
		goto out;
	for (index = 0; index < akari_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		if (!akari_generic_acl_list[index].selected)
			continue;
		akari_get();
		buf = akari_shprintf("%s", akari_generic_acl_list[index].operand);
		cp = strchr(buf, ':');
		if (cp)
			*cp = '\0';
		fprintf(fp, "%s: %s\n", buf, line);
		akari_put();
	}
	akari_close_write(fp);
out:
	free(line);
}

static _Bool akari_select_acl_window(struct akari_domain_policy *dp, const int current,
				   const _Bool may_refresh)
{
	if (akari_current_screen != AKARI_SCREEN_DOMAIN_LIST || current == EOF)
		return false;
	akari_current_pid = 0;
	if (akari_domain_sort_type) {
		akari_current_pid = akari_task_list[current].pid;
	} else if (akari_initializer_source(dp, current)) {
		char *buf;
		int redirect_index;
		if (!may_refresh)
			return false;
		akari_get();
		buf = akari_shprintf(AKARI_ROOT_NAME "%s",
			       strrchr(akari_domain_name(dp, current), ' '));
		redirect_index = akari_find_domain(dp, buf, false, false);
		akari_put();
		if (redirect_index == EOF)
			return false;
		akari_current_item_index[akari_current_screen]
			= redirect_index - akari_current_y[akari_current_screen];
		while (akari_current_item_index[akari_current_screen] < 0) {
			akari_current_item_index[akari_current_screen]++;
			akari_current_y[akari_current_screen]--;
		}
		akari_show_list(dp);
		return false;
	} else if (akari_deleted_domain(dp, current)) {
		return false;
	}
	free(akari_current_domain);
	if (akari_domain_sort_type)
		akari_current_domain = strdup(akari_task_list[current].domain);
	else
		akari_current_domain = strdup(akari_domain_name(dp, current));
	if (!akari_current_domain)
		akari_out_of_memory();
	return true;
}

static int akari_select_window(struct akari_domain_policy *dp, const int current)
{
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST && current != EOF &&
	    !akari_initializer_source(dp, current) &&
	    !akari_deleted_domain(dp, current))
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	if (!akari_offline_mode) {
		/* printw("i     <<< Interactive Enforcing Mode >>>\n"); */
		printw("u     <<< Memory Usage >>>\n");
	}
	printw("q     Quit this editor.\n");
	clrtobot();
	refresh();
	while (true) {
		int c = akari_getch2();
		if (c == 'E' || c == 'e')
			return AKARI_SCREEN_EXCEPTION_LIST;
		if (c == 'D' || c == 'd')
			return AKARI_SCREEN_DOMAIN_LIST;
		if (c == 'A' || c == 'a')
			if (akari_select_acl_window(dp, current, false))
				return AKARI_SCREEN_ACL_LIST;
		if (c == 'P' || c == 'p')
			return AKARI_SCREEN_PROFILE_LIST;
		if (c == 'M' || c == 'm')
			return AKARI_SCREEN_MANAGER_LIST;
		if (!akari_offline_mode) {
			/*
			if (c == 'I' || c == 'i')
				return AKARI_SCREEN_QUERY_LIST;
			*/
			if (c == 'U' || c == 'u')
				return AKARI_SCREEN_MEMINFO_LIST;
		}
		if (c == 'Q' || c == 'q')
			return AKARI_MAXSCREEN;
		if (c == EOF)
			return AKARI_MAXSCREEN;
	}
}

static void akari_copy_mark_state(struct akari_domain_policy *dp, const int current)
{
	int index;
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		if (akari_domain_sort_type) {
			const u8 selected = akari_task_list[current].selected;
			for (index = current; index < akari_task_list_len; index++)
				akari_task_list[index].selected = selected;
		} else {
			const u8 selected = dp->list_selected[current];
			if (akari_deleted_domain(dp, current) ||
			    akari_initializer_source(dp, current))
				return;
			for (index = current;
			     index < dp->list_len; index++) {
				if (akari_deleted_domain(dp, index) ||
				    akari_initializer_source(dp, index))
					continue;
				dp->list_selected[index] = selected;
			}
		}
	} else {
		const u8 selected = akari_generic_acl_list[current].selected;
		for (index = current; index < akari_generic_acl_list_count; index++)
			akari_generic_acl_list[index].selected = selected;
	}
	akari_show_list(dp);
}

static void akari_copy_to_history(struct akari_domain_policy *dp, const int current,
				struct akari_readline_data *rl)
{
	const char *line;
	if (current == EOF)
		return;
	akari_get();
	switch (akari_current_screen) {
		u16 directive;
	case AKARI_SCREEN_DOMAIN_LIST:
		line = akari_domain_name(dp, current);
		break;
	case AKARI_SCREEN_EXCEPTION_LIST:
	case AKARI_SCREEN_ACL_LIST:
		directive = akari_generic_acl_list[current].directive;
		line = akari_shprintf("%s %s", akari_directives[directive].alias,
				akari_generic_acl_list[current].operand);
		break;
	case AKARI_SCREEN_MEMINFO_LIST:
		line = NULL;
		break;
	default:
		line = akari_shprintf("%s", akari_generic_acl_list[current].operand);
	}
	rl->count = akari_add_history(line, rl->history, rl->count, rl->max);
	akari_put();
}

static int akari_generic_list_loop(struct akari_domain_policy *dp)
{
	static struct akari_readline_data rl;
	static int saved_current_y[AKARI_MAXSCREEN];
	static int saved_current_item_index[AKARI_MAXSCREEN];
	static _Bool first = true;
	if (first) {
		memset(&rl, 0, sizeof(rl));
		rl.max = 20;
		rl.history = malloc(rl.max * sizeof(const char *));
		memset(saved_current_y, 0, sizeof(saved_current_y));
		memset(saved_current_item_index, 0,
		       sizeof(saved_current_item_index));
		first = false;
	}
	if (akari_current_screen == AKARI_SCREEN_EXCEPTION_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_EXCEPTION_POLICY;
		akari_list_caption = "Exception Policy Editor";
	} else if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_DOMAIN_POLICY;
		akari_list_caption = "Domain Policy Editor";
	} else if (akari_current_screen == AKARI_SCREEN_QUERY_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_QUERY;
		akari_list_caption = "Interactive Enforcing Mode";
	} else if (akari_current_screen == AKARI_SCREEN_PROFILE_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_PROFILE;
		akari_list_caption = "Profile Editor";
	} else if (akari_current_screen == AKARI_SCREEN_MANAGER_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_MANAGER;
		akari_list_caption = "Manager Policy Editor";
	} else if (akari_current_screen == AKARI_SCREEN_MEMINFO_LIST) {
		akari_policy_file = AKARI_PROC_POLICY_MEMINFO;
		akari_list_caption = "Memory Usage";
	} else {
		akari_policy_file = AKARI_PROC_POLICY_DOMAIN_POLICY;
		/* akari_list_caption = "Domain Transition Editor"; */
	}
	akari_current_item_index[akari_current_screen]
		= saved_current_item_index[akari_current_screen];
	akari_current_y[akari_current_screen] = saved_current_y[akari_current_screen];
start:
	if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST) {
		if (akari_domain_sort_type == 0) {
			akari_read_domain_and_exception_policy(dp);
			akari_adjust_cursor_pos(dp->list_len);
		} else {
			akari_read_process_list(true);
			akari_adjust_cursor_pos(akari_task_list_len);
		}
	} else {
		akari_read_generic_policy();
		akari_adjust_cursor_pos(akari_generic_acl_list_count);
	}
start2:
	akari_show_list(dp);
	if (akari_last_error) {
		move(1, 0);
		printw("ERROR: %s", akari_last_error);
		clrtoeol();
		refresh();
		free(akari_last_error);
		akari_last_error = NULL;
	}
	while (true) {
		const int current = akari_editpolicy_get_current();
		const int c = akari_getch2();
		saved_current_item_index[akari_current_screen]
			= akari_current_item_index[akari_current_screen];
		saved_current_y[akari_current_screen] = akari_current_y[akari_current_screen];
		if (c == 'q' || c == 'Q')
			return AKARI_MAXSCREEN;
		if ((c == '\r' || c == '\n') &&
		    akari_current_screen == AKARI_SCREEN_ACL_LIST)
			return AKARI_SCREEN_DOMAIN_LIST;
		if (c == '\t') {
			if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST)
				return AKARI_SCREEN_EXCEPTION_LIST;
			else
				return AKARI_SCREEN_DOMAIN_LIST;
		}
		if (akari_need_reload) {
			akari_need_reload = false;
			goto start;
		}
		if (c == ERR)
			continue; /* Ignore invalid key. */
		switch (c) {
		case KEY_RESIZE:
			akari_resize_window();
			akari_show_list(dp);
			break;
		case KEY_UP:
			akari_up_arrow_key(dp);
			break;
		case KEY_DOWN:
			akari_down_arrow_key(dp);
			break;
		case KEY_PPAGE:
			akari_page_up_key(dp);
			break;
		case KEY_NPAGE:
			akari_page_down_key(dp);
			break;
		case ' ':
			akari_select_item(dp, current);
			break;
		case 'c':
		case 'C':
			if (current == EOF)
				break;
			akari_copy_mark_state(dp, current);
			akari_show_list(dp);
			break;
		case 'f':
		case 'F':
			if (akari_current_screen != AKARI_SCREEN_MEMINFO_LIST)
				akari_find_entry(dp, true, true, current, &rl);
			break;
		case 'p':
		case 'P':
			if (akari_current_screen == AKARI_SCREEN_MEMINFO_LIST)
				break;
			if (!rl.search_buffer[akari_current_screen])
				akari_find_entry(dp, true, false, current, &rl);
			else
				akari_find_entry(dp, false, false, current, &rl);
			break;
		case 'n':
		case 'N':
			if (akari_current_screen == AKARI_SCREEN_MEMINFO_LIST)
				break;
			if (!rl.search_buffer[akari_current_screen])
				akari_find_entry(dp, true, true, current, &rl);
			else
				akari_find_entry(dp, false, true, current, &rl);
			break;
		case 'd':
		case 'D':
			if (akari_readonly_mode)
				break;
			switch (akari_current_screen) {
			case AKARI_SCREEN_DOMAIN_LIST:
				if (akari_domain_sort_type)
					break;
			case AKARI_SCREEN_EXCEPTION_LIST:
			case AKARI_SCREEN_ACL_LIST:
			case AKARI_SCREEN_MANAGER_LIST:
				akari_delete_entry(dp, current);
				goto start;
			}
			break;
		case 'a':
		case 'A':
			if (akari_readonly_mode)
				break;
			switch (akari_current_screen) {
			case AKARI_SCREEN_DOMAIN_LIST:
				if (akari_domain_sort_type)
					break;
			case AKARI_SCREEN_EXCEPTION_LIST:
			case AKARI_SCREEN_ACL_LIST:
			case AKARI_SCREEN_PROFILE_LIST:
			case AKARI_SCREEN_MANAGER_LIST:
				akari_add_entry(&rl);
				goto start;
			}
			break;
		case '\r':
		case '\n':
			if (akari_select_acl_window(dp, current, true))
				return AKARI_SCREEN_ACL_LIST;
			break;
		case 's':
		case 'S':
			if (akari_readonly_mode)
				break;
			switch (akari_current_screen) {
			case AKARI_SCREEN_DOMAIN_LIST:
				akari_set_profile(dp, current);
				goto start;
			case AKARI_SCREEN_PROFILE_LIST:
				akari_set_level(dp, current);
				goto start;
			case AKARI_SCREEN_MEMINFO_LIST:
				akari_set_quota(dp, current);
				goto start;
			}
			break;
		case 'r':
		case 'R':
			goto start;
		case KEY_LEFT:
			if (!akari_max_eat_col[akari_current_screen])
				break;
			akari_max_eat_col[akari_current_screen]--;
			goto start2;
		case KEY_RIGHT:
			akari_max_eat_col[akari_current_screen]++;
			goto start2;
		case KEY_HOME:
			akari_max_eat_col[akari_current_screen] = 0;
			goto start2;
		case KEY_END:
			akari_max_eat_col[akari_current_screen] = akari_max_col;
			goto start2;
		case KEY_IC:
			akari_copy_to_history(dp, current, &rl);
			break;
		case 'o':
		case 'O':
			if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
				akari_editpolicy_try_optimize(dp, current,
							    akari_current_screen);
				akari_show_list(dp);
			}
			break;
		case '@':
			if (akari_current_screen == AKARI_SCREEN_ACL_LIST) {
				akari_acl_sort_type = (akari_acl_sort_type + 1) % 2;
				goto start;
			} else if (akari_current_screen == AKARI_SCREEN_PROFILE_LIST) {
				akari_profile_sort_type = (akari_profile_sort_type + 1) % 2;
				goto start;
			} else if (akari_current_screen == AKARI_SCREEN_DOMAIN_LIST &&
				   !akari_offline_mode) {
				akari_domain_sort_type = (akari_domain_sort_type + 1) % 2;
				goto start;
			}
			break;
		case 'w':
		case 'W':
			return akari_select_window(dp, current);
		case '?':
			if (akari_show_command_key(akari_current_screen, akari_readonly_mode))
				goto start;
			return AKARI_MAXSCREEN;
		}
	}
}

static _Bool akari_save_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = akari_editpolicy_open_read(src);
	FILE *file_fp = fopen(dest, "w");
	if (!file_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		fclose(proc_fp);
		return false;
	}
	while (true) {
		int c = fgetc(proc_fp);
		if (c == EOF)
			break;
		fputc(c, file_fp);
	}
	fclose(proc_fp);
	fclose(file_fp);
	return true;
}

int main(int argc, char *argv[])
{
	struct akari_domain_policy dp = { NULL, 0, NULL };
	struct akari_domain_policy bp = { NULL, 0, NULL };
	memset(akari_current_y, 0, sizeof(akari_current_y));
	memset(akari_current_item_index, 0, sizeof(akari_current_item_index));
	memset(akari_list_item_count, 0, sizeof(akari_list_item_count));
	memset(akari_max_eat_col, 0, sizeof(akari_max_eat_col));
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++) {
			char *ptr = argv[i];
			char *cp = strchr(ptr, ':');
			if (*ptr == '/') {
				if (akari_network_mode || akari_offline_mode)
					goto usage;
				akari_policy_dir = ptr;
				akari_offline_mode = true;
			} else if (cp) {
				*cp++ = '\0';
				if (akari_network_mode || akari_offline_mode)
					goto usage;
				akari_network_ip = inet_addr(ptr);
				akari_network_port = htons(atoi(cp));
				akari_network_mode = true;
				if (!akari_check_remote_host())
					return 1;
			} else if (!strcmp(ptr, "e"))
				akari_current_screen = AKARI_SCREEN_EXCEPTION_LIST;
			else if (!strcmp(ptr, "d"))
				akari_current_screen = AKARI_SCREEN_DOMAIN_LIST;
			else if (!strcmp(ptr, "p"))
				akari_current_screen = AKARI_SCREEN_PROFILE_LIST;
			else if (!strcmp(ptr, "m"))
				akari_current_screen = AKARI_SCREEN_MANAGER_LIST;
			else if (!strcmp(ptr, "u"))
				akari_current_screen = AKARI_SCREEN_MEMINFO_LIST;
			else if (!strcmp(ptr, "readonly"))
				akari_readonly_mode = true;
			else if (sscanf(ptr, "refresh=%u", &akari_refresh_interval)
				 != 1) {
usage:
				printf("Usage: %s [e|d|p|m|u] [readonly] "
				       "[refresh=interval] "
				       "[{policy_dir|remote_ip:remote_port}]\n",
				       argv[0]);
				return 1;
			}
		}
	}
	akari_editpolicy_init_keyword_map();
	if (akari_offline_mode) {
		int fd[2] = { EOF, EOF };
		if (chdir(akari_policy_dir)) {
			printf("Directory %s doesn't exist.\n",
			       akari_policy_dir);
			return 1;
		}
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
			fprintf(stderr, "socketpair()\n");
			exit(1);
		}
		switch (fork()) {
		case 0:
			close(fd[0]);
			akari_persistent_fd = fd[1];
			akari_editpolicy_offline_daemon();
			_exit(0);
		case -1:
			fprintf(stderr, "fork()\n");
			exit(1);
		}
		close(fd[1]);
		akari_persistent_fd = fd[0];
		akari_copy_file(AKARI_DISK_POLICY_EXCEPTION_POLICY,
			      AKARI_PROC_POLICY_EXCEPTION_POLICY);
		akari_copy_file(AKARI_DISK_POLICY_DOMAIN_POLICY, AKARI_PROC_POLICY_DOMAIN_POLICY);
		akari_copy_file(AKARI_DISK_POLICY_PROFILE, AKARI_PROC_POLICY_PROFILE);
		akari_copy_file(AKARI_DISK_POLICY_MANAGER, AKARI_PROC_POLICY_MANAGER);
	} else if (!akari_network_mode) {
		if (chdir(AKARI_PROC_POLICY_DIR)) {
			fprintf(stderr,
				"You can't use this editor for this kernel.\n");
			return 1;
		}
		if (!akari_readonly_mode) {
			const int fd1 = akari_open2(AKARI_PROC_POLICY_EXCEPTION_POLICY,
						  O_RDWR);
			const int fd2 = akari_open2(AKARI_PROC_POLICY_DOMAIN_POLICY,
						  O_RDWR);
			if ((fd1 != EOF && write(fd1, "", 0) != 0) ||
			    (fd2 != EOF && write(fd2, "", 0) != 0)) {
				fprintf(stderr,
					"You need to register this program to "
					"%s to run this program.\n",
					AKARI_PROC_POLICY_MANAGER);
				return 1;
			}
			close(fd1);
			close(fd2);
		}
	}
	initscr();
	akari_editpolicy_color_init();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	getmaxyx(stdscr, akari_window_height, akari_window_width);
	if (akari_refresh_interval) {
		signal(SIGALRM, akari_sigalrm_handler);
		alarm(akari_refresh_interval);
		timeout(1000);
	}
	while (akari_current_screen < AKARI_MAXSCREEN) {
		akari_resize_window();
		akari_current_screen = akari_generic_list_loop(&dp);
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (akari_offline_mode && !akari_readonly_mode) {
		time_t now = time(NULL);
		const char *filename = akari_make_filename("exception_policy", now);
		if (akari_save_to_file(AKARI_PROC_POLICY_EXCEPTION_POLICY, filename)) {
			if (akari_identical_file("exception_policy.conf",
						  filename)) {
				unlink(filename);
			} else {
				unlink("exception_policy.conf");
				symlink(filename, "exception_policy.conf");
			}
		}
		akari_clear_domain_policy(&dp);
		filename = akari_make_filename("domain_policy", now);
		if (akari_save_to_file(AKARI_PROC_POLICY_DOMAIN_POLICY, filename)) {
			if (akari_identical_file("domain_policy.conf", filename)) {
				unlink(filename);
			} else {
				unlink("domain_policy.conf");
				symlink(filename, "domain_policy.conf");
			}
		}
		filename = akari_make_filename("profile", now);
		if (akari_save_to_file(AKARI_PROC_POLICY_PROFILE, filename)) {
			if (akari_identical_file("profile.conf", filename)) {
				unlink(filename);
			} else {
				unlink("profile.conf");
				symlink(filename, "profile.conf");
			}
		}
		filename = akari_make_filename("manager", now);
		if (akari_save_to_file(AKARI_PROC_POLICY_MANAGER, filename)) {
			if (akari_identical_file("manager.conf", filename)) {
				unlink(filename);
			} else {
				unlink("manager.conf");
				symlink(filename, "manager.conf");
			}
		}
	}
	akari_clear_domain_policy(&bp);
	akari_clear_domain_policy(&dp);
	return 0;
}
