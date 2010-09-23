/*
 * akari-diffpolicy.c
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

int main(int argc, char *argv[])
{
	struct akari_domain_policy old_policy = { NULL, 0, NULL };
	struct akari_domain_policy new_policy = { NULL, 0, NULL };
	const struct akari_path_info **old_string_ptr;
	const struct akari_path_info **new_string_ptr;
	int old_string_count;
	int new_string_count;
	int old_index;
	int new_index;
	const struct akari_path_info *domainname;
	int i;
	int j;
	const char *old = NULL;
	const char *new = NULL;
	if (argc != 3)
		goto usage;
	old = argv[1];
	new = argv[2];
	if (!strcmp(new, "-"))
		new = NULL;
	if (!strcmp(old, "-"))
		old = NULL;
	if (!new && !old) {
usage:
		printf("%s old_domain_policy new_domain_policy\n"
		       "- : Read policy from stdin.\n", argv[0]);
		return 0;
	}
	akari_read_domain_policy(&old_policy, old);
	akari_read_domain_policy(&new_policy, new);
	for (old_index = 0; old_index < old_policy.list_len; old_index++) {
		domainname = old_policy.list[old_index].domainname;
		new_index = akari_find_domain_by_ptr(&new_policy, domainname);
		if (new_index >= 0)
			continue;
		/* This domain was deleted. */
		printf("delete %s\n\n", domainname->name);
	}
	for (new_index = 0; new_index < new_policy.list_len; new_index++) {
		domainname = new_policy.list[new_index].domainname;
		old_index = akari_find_domain_by_ptr(&old_policy, domainname);
		if (old_index >= 0)
			continue;
		/* This domain was added. */
		printf("%s\n\n", domainname->name);
		if (new_policy.list[new_index].profile_assigned)
			printf("use_profile %u\n",
			       new_policy.list[new_index].profile);
		new_string_ptr = new_policy.list[new_index].string_ptr;
		new_string_count = new_policy.list[new_index].string_count;
		for (i = 0; i < new_string_count; i++)
			printf("%s\n", new_string_ptr[i]->name);
		printf("\n");
	}
	for (old_index = 0; old_index < old_policy.list_len; old_index++) {
		_Bool first = true;
		domainname = old_policy.list[old_index].domainname;
		new_index = akari_find_domain_by_ptr(&new_policy, domainname);
		if (new_index == EOF)
			continue;
		/* This domain exists in both old policy and new policy. */
		old_string_ptr = old_policy.list[old_index].string_ptr;
		old_string_count = old_policy.list[old_index].string_count;
		new_string_ptr = new_policy.list[new_index].string_ptr;
		new_string_count = new_policy.list[new_index].string_count;
		for (i = 0; i < old_string_count; i++) {
			for (j = 0; j < new_string_count; j++) {
				if (old_string_ptr[i] != new_string_ptr[j])
					continue;
				old_string_ptr[i] = NULL;
				new_string_ptr[j] = NULL;
			}
		}
		for (i = 0; i < new_string_count; i++) {
			if (!new_string_ptr[i])
				continue;
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			printf("delete %s\n", new_string_ptr[i]->name);
		}
		for (i = 0; i < old_string_count; i++) {
			if (!old_string_ptr[i])
				continue;
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			printf("%s\n", old_string_ptr[i]->name);
		}
		if (old_policy.list[old_index].profile !=
		    new_policy.list[new_index].profile) {
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			if (old_policy.list[old_index].profile_assigned)
				printf("use_profile %u\n",
				       old_policy.list[old_index].profile);
		}
		if (!first)
			printf("\n");
	}
	return 0;
}
