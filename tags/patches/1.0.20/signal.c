/*
 * security/ccsecurity/signal.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
 */

#include "internal.h"

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid ccsecurity_exports.find_task_by_vpid
#endif

/**
 * ccs_audit_signal_log - Audit signal log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_signal_log(struct ccs_request_info *r)
{
	return ccs_supervisor(r, "ipc signal %d %s\n", r->param.signal.sig,
			      r->param.signal.dest_pattern);
}

/**
 * ccs_check_signal_acl - Check permission for signal operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_signal_acl(struct ccs_request_info *r,
				 const struct ccs_acl_info *ptr)
{
	const struct ccs_signal_acl *acl =
		container_of(ptr, typeof(*acl), head);
	if (ccs_compare_number_union(r->param.signal.sig, &acl->sig)) {
		const int len = acl->domainname->total_len;
		if (!strncmp(acl->domainname->name,
			     r->param.signal.dest_pattern, len)) {
			switch (r->param.signal.dest_pattern[len]) {
			case ' ':
			case '\0':
				return true;
			}
		}
	}
	return false;
}

/**
 * ccs_signal_acl2 - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_signal_acl2(const int sig, const int pid)
{
	struct ccs_request_info r;
	struct ccs_domain_info *dest = NULL;
	int error;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	if (ccs_init_request_info(&r, CCS_MAC_SIGNAL) == CCS_CONFIG_DISABLED)
		return 0;
	if (!sig)
		return 0;                /* No check for NULL signal. */
	r.param_type = CCS_TYPE_SIGNAL_ACL;
	r.param.signal.sig = sig;
	r.param.signal.dest_pattern = domain->domainname->name;
	r.granted = true;
	if (ccs_sys_getpid() == pid) {
		ccs_audit_signal_log(&r);
		return 0;                /* No check for self process. */
	}
	{ /* Simplified checking. */
		struct task_struct *p = NULL;
		ccs_tasklist_lock();
		if (pid > 0)
			p = find_task_by_pid((pid_t) pid);
		else if (pid == 0)
			p = current;
		else if (pid == -1)
			dest = &ccs_kernel_domain;
		else
			p = find_task_by_pid((pid_t) -pid);
		if (p)
			dest = ccs_task_domain(p);
		ccs_tasklist_unlock();
	}
	if (!dest)
		return 0; /* I can't find destinatioin. */
	if (domain == dest) {
		ccs_audit_signal_log(&r);
		return 0;                /* No check for self domain. */
	}
	r.param.signal.dest_pattern = dest->domainname->name;
	do {
		ccs_check_acl(&r, ccs_check_signal_acl);
		error = ccs_audit_signal_log(&r);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

/**
 * ccs_signal_acl - Check permission for signal.
 *
 * @pid: Target's PID.
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_acl(const int pid, const int sig)
{
	int error;
	if (!sig)
		error = 0;
	else {
		const int idx = ccs_read_lock();
		error = ccs_signal_acl2(sig, pid);
		ccs_read_unlock(idx);
	}
	return error;
}

/**
 * ccs_signal_acl0 - Permission check for signal().
 *
 * @tgid: Unused.
 * @pid:  Target's PID.
 * @sig:  Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_acl0(pid_t tgid, pid_t pid, int sig)
{
	return ccs_signal_acl(pid, sig);
}

/**
 * ccs_same_signal_acl - Check for duplicated "struct ccs_signal_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_signal_acl(const struct ccs_acl_info *a,
				const struct ccs_acl_info *b)
{
	const struct ccs_signal_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_signal_acl *p2 = container_of(b, typeof(*p2), head);
	return ccs_same_number_union(&p1->sig, &p2->sig) &&
		p1->domainname == p2->domainname;
}

/**
 * ccs_write_ipc - Update "struct ccs_signal_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_ipc(struct ccs_acl_param *param)
{
	struct ccs_signal_acl e = { .head.type = CCS_TYPE_SIGNAL_ACL };
	int error;
	if (!ccs_parse_number_union(param, &e.sig))
		return -EINVAL;
	e.domainname = ccs_get_domainname(param);
	if (!e.domainname)
		error = -EINVAL;
	else
		error = ccs_update_domain(&e.head, sizeof(e), param,
					  ccs_same_signal_acl, NULL);
	ccs_put_name(e.domainname);
	ccs_put_number_union(&e.sig);
	return error;
}

/**
 * ccs_signal_init - Register ipc related hooks.
 *
 * Returns nothing.
 */
void __init ccs_signal_init(void)
{
	ccsecurity_ops.kill_permission = ccs_signal_acl;
	ccsecurity_ops.tgkill_permission = ccs_signal_acl0;
	ccsecurity_ops.tkill_permission = ccs_signal_acl;
	ccsecurity_ops.sigqueue_permission = ccs_signal_acl;
	ccsecurity_ops.tgsigqueue_permission = ccs_signal_acl0;
}
