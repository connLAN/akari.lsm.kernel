/*
 * security/ccsecurity/group.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

static bool ccs_same_path_group(const struct ccs_acl_head *a,
				const struct ccs_acl_head *b)
{
	return container_of(a, struct ccs_path_group, head)->member_name ==
		container_of(b, struct ccs_path_group, head)->member_name;
}

static bool ccs_same_number_group(const struct ccs_acl_head *a,
				  const struct ccs_acl_head *b)
{
	return !memcmp(&container_of(a, struct ccs_number_group, head)->number,
		       &container_of(b, struct ccs_number_group, head)->number,
		       sizeof(container_of(a, struct ccs_number_group, head)
			      ->number));
}

static bool ccs_same_address_group(const struct ccs_acl_head *a,
				   const struct ccs_acl_head *b)
{
	const struct ccs_address_group *p1 = container_of(a, typeof(*p1),
							  head);
	const struct ccs_address_group *p2 = container_of(b, typeof(*p2),
							  head);
	return p1->is_ipv6 == p2->is_ipv6 &&
		p1->min.ipv4 == p2->min.ipv4 && p1->min.ipv6 == p2->min.ipv6 &&
		p1->max.ipv4 == p2->max.ipv4 && p1->max.ipv6 == p2->max.ipv6;
}

/**
 * ccs_write_group - Write "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 * @type:      Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_group(char *data, const bool is_delete, const u8 type)
{
	struct ccs_group *group;
	struct list_head *member;
	char *w[2];
	int error = -EINVAL;
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	group = ccs_get_group(w[0], type);
	if (!group)
		return -ENOMEM;
	member = &group->member_list;
	if (type == CCS_PATH_GROUP) {
		struct ccs_path_group e = { };
		e.member_name = ccs_get_name(w[1]);
		if (!e.member_name) {
			error = -ENOMEM;
			goto out;
		}
		error = ccs_update_policy(&e.head, sizeof(e), is_delete,
					  member, ccs_same_path_group);
		ccs_put_name(e.member_name);
	} else if (type == CCS_NUMBER_GROUP) {
		struct ccs_number_group e = { };
		if (w[1][0] == '@' || !ccs_parse_number_union(w[1], &e.number)
		    || e.number.values[0] > e.number.values[1])
			goto out;
		error = ccs_update_policy(&e.head, sizeof(e), is_delete,
					  member, ccs_same_number_group);
		/*
		 * ccs_put_number_union() is not needed because w[1][0] != '@'.
		 */
	} else {
		struct ccs_address_group e = { };
		u16 min_address[8];
		u16 max_address[8];
		switch (ccs_parse_ip_address(w[1], min_address, max_address)) {
		case CCS_IP_ADDRESS_TYPE_IPv6:
			e.is_ipv6 = true;
			e.min.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
							  min_address);
			e.max.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
							  max_address);
			if (!e.min.ipv6 || !e.max.ipv6)
				goto out_address;
			break;
		case CCS_IP_ADDRESS_TYPE_IPv4:
			e.min.ipv4 = ntohl(*(u32 *) min_address);
			e.max.ipv4 = ntohl(*(u32 *) max_address);
			break;
		default:
			goto out_address;
		}
		error = ccs_update_policy(&e.head, sizeof(e), is_delete,
					  member, ccs_same_address_group);
out_address:
		if (e.is_ipv6) {
			ccs_put_ipv6_address(e.min.ipv6);
			ccs_put_ipv6_address(e.max.ipv6);
		}
	}
out:
	ccs_put_group(group);
	return error;
}

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname:        The name of pathname.
 * @group:           Pointer to "struct ccs_path_group".
 *
 * Returns matched member's pathname if @pathname matches pathnames in @group,
 * NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
const struct ccs_path_info *
ccs_path_matches_group(const struct ccs_path_info *pathname,
		       const struct ccs_group *group)
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
	const u32 ip = ntohl(*address);
	bool matched = false;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (member->is_ipv6) {
			if (is_ipv6 &&
			    memcmp(member->min.ipv6, address, 16) <= 0 &&
			    memcmp(address, member->max.ipv6, 16) <= 0) {
				matched = true;
				break;
			}
		} else {
			if (!is_ipv6 &&
			    member->min.ipv4 <= ip && ip <= member->max.ipv4) {
				matched = true;
				break;
			}
		}
	}
	return matched;
}
