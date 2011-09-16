/*
 * security/ccsecurity/autobind.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3-pre   2011/09/16
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
	return ccs_same_number_union(&p1->port, &p2->port);
}

/**
 * ccs_write_reserved_port - Update "struct ccs_reserved" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_write_reserved_port(struct ccs_acl_param *param)
{
	struct ccs_reserved e = { };
	struct ccs_policy_namespace *ns = param->ns;
	int error;
	u8 *tmp;
	if (param->data[0] == '@' || !ccs_parse_number_union(param, &e.port) ||
	    e.port.values[1] > 65535 || param->data[0])
		return -EINVAL;
	param->list = &ns->policy_list[CCS_ID_RESERVEDPORT];
	error = ccs_update_policy(&e.head, sizeof(e), param,
				  ccs_same_reserved);
	/*
	 * ccs_put_number_union() is not needed because param->data[0] != '@'.
	 */
	if (error)
		return error;
	tmp = kzalloc(sizeof(ccs_reserved_port_map), CCS_GFP_FLAGS);
	if (!tmp)
		return -ENOMEM;
	list_for_each_entry_srcu(ns, &ccs_namespace_list, namespace_list,
				 &ccs_ss) {
		struct ccs_reserved *ptr;
		struct list_head *list = &ns->policy_list[CCS_ID_RESERVEDPORT];
		list_for_each_entry_srcu(ptr, list, head.list, &ccs_ss) {
			unsigned int port;
			if (ptr->head.is_deleted)
				continue;
			for (port = ptr->port.values[0];
			     port <= ptr->port.values[1]; port++)
				tmp[port >> 3] |= 1 << (port & 7);
		}
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
