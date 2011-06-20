/*
 * security/ccsecurity/capability.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
 */

#include "internal.h"

/*
 * Mapping table from "enum ccs_capability_acl_index" to "enum ccs_mac_index".
 */
const u8 ccs_c2mac[CCS_MAX_CAPABILITY_INDEX] = {
	[CCS_USE_ROUTE_SOCKET]  = CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	[CCS_USE_PACKET_SOCKET] = CCS_MAC_CAPABILITY_USE_PACKET_SOCKET,
	[CCS_SYS_REBOOT]        = CCS_MAC_CAPABILITY_SYS_REBOOT,
	[CCS_SYS_VHANGUP]       = CCS_MAC_CAPABILITY_SYS_VHANGUP,
	[CCS_SYS_SETTIME]       = CCS_MAC_CAPABILITY_SYS_SETTIME,
	[CCS_SYS_NICE]          = CCS_MAC_CAPABILITY_SYS_NICE,
	[CCS_SYS_SETHOSTNAME]   = CCS_MAC_CAPABILITY_SYS_SETHOSTNAME,
	[CCS_USE_KERNEL_MODULE] = CCS_MAC_CAPABILITY_USE_KERNEL_MODULE,
	[CCS_SYS_KEXEC_LOAD]    = CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD,
	[CCS_SYS_PTRACE]        = CCS_MAC_CAPABILITY_SYS_PTRACE,
};

/**
 * ccs_audit_capability_log - Audit capability log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_capability_log(struct ccs_request_info *r)
{
	return ccs_supervisor(r, "capability %s\n", ccs_mac_keywords
			      [ccs_c2mac[r->param.capability.operation]]);
}

/**
 * ccs_check_capability_acl - Check permission for capability operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_capability_acl(struct ccs_request_info *r,
				     const struct ccs_acl_info *ptr)
{
	const struct ccs_capability_acl *acl =
		container_of(ptr, typeof(*acl), head);
	return acl->operation == r->param.capability.operation;
}

/**
 * ccs_capable - Check permission for capability.
 *
 * @operation: Type of operation.
 *
 * Returns true on success, false otherwise.
 */
static bool __ccs_capable(const u8 operation)
{
	struct ccs_request_info r;
	int error = 0;
	const int idx = ccs_read_lock();
	if (ccs_init_request_info(&r, ccs_c2mac[operation])
	    != CCS_CONFIG_DISABLED) {
		r.param_type = CCS_TYPE_CAPABILITY_ACL;
		r.param.capability.operation = operation;
		do {
			ccs_check_acl(&r, ccs_check_capability_acl);
			error = ccs_audit_capability_log(&r);
		} while (error == CCS_RETRY_REQUEST);
	}
	ccs_read_unlock(idx);
	return !error;
}

/**
 * __ccs_ptrace_permission - Check permission for ptrace().
 *
 * @request: Unused.
 * @pid:     Unused.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Since this function is called from location where it is permitted to sleep,
 * it is racy to check target process's domainname anyway. Therefore, we don't
 * use target process's domainname.
 */
static int __ccs_ptrace_permission(long request, long pid)
{
	return __ccs_capable(CCS_SYS_PTRACE) ? 0 : -EPERM;
}

/**
 * ccs_same_capability_acl - Check for duplicated "struct ccs_capability_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_capability_acl(const struct ccs_acl_info *a,
				    const struct ccs_acl_info *b)
{
	const struct ccs_capability_acl *p1 = container_of(a, typeof(*p1),
							   head);
	const struct ccs_capability_acl *p2 = container_of(b, typeof(*p2),
							   head);
	return p1->operation == p2->operation;
}

/**
 * ccs_write_capability - Write "struct ccs_capability_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_write_capability(struct ccs_acl_param *param)
{
	struct ccs_capability_acl e = { .head.type = CCS_TYPE_CAPABILITY_ACL };
	const char *operation = ccs_read_token(param);
	for (e.operation = 0; e.operation < CCS_MAX_CAPABILITY_INDEX;
	     e.operation++) {
		if (strcmp(operation,
			   ccs_mac_keywords[ccs_c2mac[e.operation]]))
			continue;
		return ccs_update_domain(&e.head, sizeof(e), param,
					 ccs_same_capability_acl, NULL);
	}
	return -EINVAL;
}

/**
 * ccs_capability_init - Register capability related hooks.
 *
 * Returns nothing.
 */
void __init ccs_capability_init(void)
{
	ccsecurity_ops.capable = __ccs_capable;
	ccsecurity_ops.ptrace_permission = __ccs_ptrace_permission;
}
