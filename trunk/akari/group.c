/*
 * security/ccsecurity/group.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3-rc   2011/09/29
 */

#include "internal.h"

/**
 * ccs_same_path_group - Check for duplicated "struct ccs_path_group" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_path_group(const struct ccs_acl_head *a,
				const struct ccs_acl_head *b)
{
	return container_of(a, struct ccs_path_group, head)->member_name ==
		container_of(b, struct ccs_path_group, head)->member_name;
}

/**
 * ccs_same_number_group - Check for duplicated "struct ccs_number_group" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_number_group(const struct ccs_acl_head *a,
				  const struct ccs_acl_head *b)
{
	return !memcmp(&container_of(a, struct ccs_number_group, head)->number,
		       &container_of(b, struct ccs_number_group, head)->number,
		       sizeof(container_of(a, struct ccs_number_group, head)
			      ->number));
}

/**
 * ccs_same_address_group - Check for duplicated "struct ccs_address_group" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_address_group(const struct ccs_acl_head *a,
				   const struct ccs_acl_head *b)
{
	const struct ccs_address_group *p1 = container_of(a, typeof(*p1),
							  head);
	const struct ccs_address_group *p2 = container_of(b, typeof(*p2),
							  head);
	return ccs_same_ipaddr_union(&p1->address, &p2->address);
}

/**
 * ccs_write_group - Write "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @type:  Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_group(struct ccs_acl_param *param, const u8 type)
{
	struct ccs_group *group = ccs_get_group(param, type);
	int error = -EINVAL;
	if (!group)
		return -ENOMEM;
	param->list = &group->member_list;
	if (type == CCS_PATH_GROUP) {
		struct ccs_path_group e = { };
		e.member_name = ccs_get_name(ccs_read_token(param));
		if (!e.member_name) {
			error = -ENOMEM;
			goto out;
		}
		error = ccs_update_policy(&e.head, sizeof(e), param,
					  ccs_same_path_group);
		ccs_put_name(e.member_name);
	} else if (type == CCS_NUMBER_GROUP) {
		struct ccs_number_group e = { };
		if (param->data[0] == '@' ||
		    !ccs_parse_number_union(param, &e.number))
			goto out;
		error = ccs_update_policy(&e.head, sizeof(e), param,
					  ccs_same_number_group);
		/*
		 * ccs_put_number_union() is not needed because
		 * param->data[0] != '@'.
		 */
	} else {
		struct ccs_address_group e = { };
		if (param->data[0] == '@' ||
		    !ccs_parse_ipaddr_union(param, &e.address))
			goto out;
		error = ccs_update_policy(&e.head, sizeof(e), param,
					  ccs_same_address_group);
	}
out:
	ccs_put_group(group);
	return error;
}

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname: The name of pathname.
 * @group:    Pointer to "struct ccs_path_group".
 *
 * Returns matched member's pathname if @pathname matches pathnames in @group,
 * NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
const struct ccs_path_info *ccs_path_matches_group
(const struct ccs_path_info *pathname, const struct ccs_group *group)
{
	struct ccs_path_group *member;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (!ccs_path_matches_pattern(pathname, member->member_name))
			continue;
		return member->member_name;
	}
	return NULL;
}

/**
 * ccs_number_matches_group - Check whether the given number matches members of the given number group.
 *
 * @min:   Min number.
 * @max:   Max number.
 * @group: Pointer to "struct ccs_number_group".
 *
 * Returns true if @min and @max partially overlaps @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_group *group)
{
	struct ccs_number_group *member;
	bool matched = false;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (min > member->number.values[1] ||
		    max < member->number.values[0])
			continue;
		matched = true;
		break;
	}
	return matched;
}

/**
 * ccs_address_matches_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_address_group".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
			       const struct ccs_group *group)
{
	struct ccs_address_group *member;
	bool matched = false;
	const u8 size = is_ipv6 ? 16 : 4;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (member->address.is_ipv6 != is_ipv6)
			continue;
		if (memcmp(&member->address.ip[0], address, size) > 0 ||
		    memcmp(address, &member->address.ip[1], size) > 0)
			continue;
		matched = true;
		break;
	}
	return matched;
}
