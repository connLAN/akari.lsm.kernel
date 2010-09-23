/*
 * editpolicy_color.c
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

#ifdef COLOR_ON

void akari_editpolicy_color_init(void)
{
	static struct akari_color_env_t {
		enum akari_color_pair tag;
		short int fore;
		short int back;
		const char *name;
	} color_env[] = {
		{ AKARI_DOMAIN_HEAD,      COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_HEAD" },
		{ AKARI_DOMAIN_CURSOR,    COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_CURSOR" },
		{ AKARI_EXCEPTION_HEAD,   COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_HEAD" },
		{ AKARI_EXCEPTION_CURSOR, COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_CURSOR" },
		{ AKARI_ACL_HEAD,         COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_HEAD" },
		{ AKARI_ACL_CURSOR,       COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_CURSOR" },
		{ AKARI_PROFILE_HEAD,     COLOR_WHITE,
		  COLOR_RED,        "PROFILE_HEAD" },
		{ AKARI_PROFILE_CURSOR,   COLOR_WHITE,
		  COLOR_RED,        "PROFILE_CURSOR" },
		{ AKARI_MANAGER_HEAD,     COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_HEAD" },
		{ AKARI_MANAGER_CURSOR,   COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_CURSOR" },
		{ AKARI_MEMORY_HEAD,      COLOR_BLACK,
		  COLOR_YELLOW,     "MEMORY_HEAD" },
		{ AKARI_MEMORY_CURSOR,    COLOR_BLACK,
		  COLOR_YELLOW,     "MEMORY_CURSOR" },
		{ AKARI_NORMAL,           COLOR_WHITE,
		  COLOR_BLACK,      NULL }
	};
	FILE *fp = fopen(AKARI_CONFIG_FILE, "r");
	int i;
	if (!fp)
		goto use_default;
	akari_get();
	while (true) {
		char *line = akari_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!akari_str_starts(line, "editpolicy.line_color "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		akari_normalize_line(line);
		akari_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 0; color_env[i].name; i++) {
			short int fore;
			short int back;
			if (strcmp(line, color_env[i].name))
				continue;
			if (strlen(cp) != 2)
				break;
			fore = (*cp++) - '0'; /* foreground color */
			back = (*cp) - '0';   /* background color */
			if (fore < 0 || fore > 7 || back < 0 || back > 7)
				break;
			color_env[i].fore = fore;
			color_env[i].back = back;
			break;
		}
	}
	akari_put();
	fclose(fp);
use_default:
	start_color();
	for (i = 0; color_env[i].name; i++) {
		struct akari_color_env_t *colorp = &color_env[i];
		init_pair(colorp->tag, colorp->fore, colorp->back);
	}
	init_pair(AKARI_DISP_ERR, COLOR_RED, COLOR_BLACK); /* error message */
}

static void akari_editpolicy_color_save(const _Bool flg)
{
	static attr_t save_color = AKARI_NORMAL;
	if (flg)
		save_color = getattrs(stdscr);
	else
		attrset(save_color);
}

void akari_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(COLOR_PAIR(attr));
	else
		attroff(COLOR_PAIR(attr));
}

void akari_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(attr);
	else
		attroff(attr);
}

void akari_editpolicy_sttr_save(void)
{
	akari_editpolicy_color_save(true);
}

void akari_editpolicy_sttr_restore(void)
{
	akari_editpolicy_color_save(false);
}

int akari_editpolicy_color_head(const int screen)
{
	switch (screen) {
	case AKARI_SCREEN_DOMAIN_LIST:
		return AKARI_DOMAIN_HEAD;
	case AKARI_SCREEN_EXCEPTION_LIST:
		return AKARI_EXCEPTION_HEAD;
	case AKARI_SCREEN_PROFILE_LIST:
		return AKARI_PROFILE_HEAD;
	case AKARI_SCREEN_MANAGER_LIST:
		return AKARI_MANAGER_HEAD;
	case AKARI_SCREEN_MEMINFO_LIST:
		return AKARI_MEMORY_HEAD;
	default:
		return AKARI_ACL_HEAD;
	}
}

int akari_editpolicy_color_cursor(const int screen)
{
	switch (screen) {
	case AKARI_SCREEN_DOMAIN_LIST:
		return AKARI_DOMAIN_CURSOR;
	case AKARI_SCREEN_EXCEPTION_LIST:
		return AKARI_EXCEPTION_CURSOR;
	case AKARI_SCREEN_PROFILE_LIST:
		return AKARI_PROFILE_CURSOR;
	case AKARI_SCREEN_MANAGER_LIST:
		return AKARI_MANAGER_CURSOR;
	case AKARI_SCREEN_MEMINFO_LIST:
		return AKARI_MEMORY_CURSOR;
	default:
		return AKARI_ACL_CURSOR;
	}
}

void akari_editpolicy_line_draw(const int screen)
{
	static int akari_before_current[AKARI_MAXSCREEN] = { -1, -1, -1, -1,
							 -1, -1, -1 };
	static int akari_before_y[AKARI_MAXSCREEN]       = { -1, -1, -1, -1,
							 -1, -1, -1 };
	int current = akari_editpolicy_get_current();
	int y;
	int x;

	if (current == EOF)
		return;

	getyx(stdscr, y, x);
	if (-1 < akari_before_current[screen] &&
	    current != akari_before_current[screen]){
		move(AKARI_HEADER_LINES + akari_before_y[screen], 0);
		chgat(-1, A_NORMAL, AKARI_NORMAL, NULL);
	}

	move(y, x);
	chgat(-1, A_NORMAL, akari_editpolicy_color_cursor(screen), NULL);
	touchwin(stdscr);

	akari_before_current[screen] = current;
	akari_before_y[screen] = akari_current_y[screen];
}

#else

void akari_editpolicy_color_init(void)
{
}
void akari_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
}
void akari_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
}
void akari_editpolicy_sttr_save(void)
{
}
void akari_editpolicy_sttr_restore(void)
{
}
int akari_editpolicy_color_head(const int screen)
{
}
int akari_editpolicy_color_cursor(const int screen)
{
}
void akari_editpolicy_line_draw(const int screen)
{
}

#endif
