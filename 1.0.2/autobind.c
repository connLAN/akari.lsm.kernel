/*
 * security/ccsecurity/autobind.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/25
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/* Bitmap for reserved local port numbers.*/
static u8 ccs_reserved_port_map[8192];

/**
 * ccs_lport_reserved - Check whether local port is reserved or not.
 *
 * @port: Port number.
 *
 * Returns true if local port is reserved, false otherwise.
 */
static bool __ccs_lport_reserved(const u16 port)
{
	return ccs_reserved_port_map[port >> 3] & (1 << (port & 7))
		? true : false;
}

/**
 * ccs_same_reserved - Check for duplicated "struct ccs_reserved" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_reserved(const struct ccs_acl_head *a,
			      const struct ccs_acl_head *b)
{
	const struct ccs_reserved *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_reserved *p2 = container_of(b, typeof(*p2), head);
	return p1->min_port == p2->min_port && p1->max_port == p2->max_port;
}

/**
 * ccs_update_reserved_entry - Update "struct ccs_reserved" list.
 *
 * @min_port:  Start of port number range.
 * @max_port:  End of port number range.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_reserved_entry(const u16 min_port, const u16 max_port,
				     const bool is_delete)
{
	struct ccs_reserved *ptr;
	struct ccs_reserved e = {
		.min_port = min_port,
		.max_port = max_port
	};
	const int error =
		ccs_update_policy(&e.head, sizeof(e), is_delete,
				  &ccs_policy_list[CCS_ID_RESERVEDPORT],
				  ccs_same_reserved);
	u8 *tmp;
	if (error)
		return error;
	tmp = kzalloc(sizeof(ccs_reserved_port_map), CCS_GFP_FLAGS);
	if (!tmp)
		return -ENOMEM;
	list_for_each_entry_srcu(ptr, &ccs_policy_list[CCS_ID_RESERVEDPORT],
				 head.list, &ccs_ss) {
		unsigned int port;
		if (ptr->head.is_deleted)
			continue;
		for (port = ptr->min_port; port <= ptr->max_port; port++)
			tmp[port >> 3] |= 1 << (port & 7);
	}
	memmove(ccs_reserved_port_map, tmp, sizeof(ccs_reserved_port_map));
	kfree(tmp);
	/*
	 * Since this feature is no-op by default, we don't need to register
	 * this callback hook unless the first entry is added.
	 */
	ccsecurity_ops.lport_reserved = __ccs_lport_reserved;
	return 0;
}

/**
 * ccs_write_reserved_port - Write "struct ccs_reserved" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_reserved_port(char *data, const bool is_delete)
{
	unsigned int from;
	unsigned int to;
	if (strchr(data, ' '))
		goto out;
	switch (sscanf(data, "%u-%u", &from, &to)) {
	case 1:
		to = from;
		/* fall through */
	case 2:
		if (from <= to && to < 65536)
			return ccs_update_reserved_entry(from, to,
							 is_delete);
		break;
	}
out:
	return -EINVAL;
}
