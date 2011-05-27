/*
 * security/ccsecurity/audit.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2-pre   2011/05/22
 */

#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

/**
 * fatal_signal_pending - Check whether SIGKILL is pending or not.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns true if SIGKILL is pending on @p, false otherwise.
 *
 * This is for compatibility with older kernels.
 */
#define fatal_signal_pending(p) (signal_pending(p) &&			\
				 sigismember(&p->pending.signal, SIGKILL))

#endif

/**
 * ccs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct ccs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump)
{
	static const int ccs_buffer_len = 4096 * 2;
	char *buffer = kzalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	char *cp;
	char *last_start;
	int len;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool truncated = false;
	if (!buffer)
		return NULL;
	len = snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ");
	cp = buffer + len;
	if (!argv_count) {
		memmove(cp, "} envp[]={ ", 11);
		cp += 11;
	}
	last_start = cp;
	while (argv_count || envp_count) {
		if (!ccs_dump_page(bprm, pos, dump))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			if (cp == last_start)
				*cp++ = '"';
			if (cp >= buffer + ccs_buffer_len - 32) {
				/* Reserve some room for "..." string. */
				truncated = true;
			} else if (c == '\\') {
				*cp++ = '\\';
				*cp++ = '\\';
			} else if (c > ' ' && c < 127) {
				*cp++ = c;
			} else if (!c) {
				*cp++ = '"';
				*cp++ = ' ';
				last_start = cp;
			} else {
				*cp++ = '\\';
				*cp++ = (c >> 6) + '0';
				*cp++ = ((c >> 3) & 7) + '0';
				*cp++ = (c & 7) + '0';
			}
			if (c)
				continue;
			if (argv_count) {
				if (--argv_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
					memmove(cp, "} envp[]={ ", 11);
					cp += 11;
					last_start = cp;
					truncated = false;
				}
			} else if (envp_count) {
				if (--envp_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
				}
			}
			if (!argv_count && !envp_count)
				break;
		}
		offset = 0;
	}
	*cp++ = '}';
	*cp = '\0';
	return buffer;
out:
	snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ... } envp[]= { ... }");
	return buffer;
}

/**
 * ccs_filetype - Get string representation of file type.
 *
 * @mode: Mode value for stat().
 *
 * Returns file type string.
 */
static inline const char *ccs_filetype(const mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		return ccs_condition_keyword[CCS_TYPE_IS_FILE];
	case S_IFDIR:
		return ccs_condition_keyword[CCS_TYPE_IS_DIRECTORY];
	case S_IFLNK:
		return ccs_condition_keyword[CCS_TYPE_IS_SYMLINK];
	case S_IFIFO:
		return ccs_condition_keyword[CCS_TYPE_IS_FIFO];
	case S_IFSOCK:
		return ccs_condition_keyword[CCS_TYPE_IS_SOCKET];
	case S_IFBLK:
		return ccs_condition_keyword[CCS_TYPE_IS_BLOCK_DEV];
	case S_IFCHR:
		return ccs_condition_keyword[CCS_TYPE_IS_CHAR_DEV];
	}
	return "unknown"; /* This should not happen. */
}

/**
 * ccs_print_header - Get header line of audit log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns string representation.
 *
 * This function uses kmalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_header(struct ccs_request_info *r)
{
	struct ccs_time stamp;
	struct ccs_obj_info *obj = r->obj;
	const u32 ccs_flags = ccs_current_flags();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	const pid_t gpid = ccs_sys_getpid();
#else
	const pid_t gpid = task_pid_nr(current);
#endif
	static const int ccs_buffer_len = 4096;
	char *buffer = kmalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	int pos;
	u8 i;
	if (!buffer)
		return NULL;
	{
		struct timeval tv;
		do_gettimeofday(&tv);
		ccs_convert_time(tv.tv_sec, &stamp);
	}
	pos = snprintf(buffer, ccs_buffer_len - 1,
		       "#%04u/%02u/%02u %02u:%02u:%02u# profile=%u mode=%s "
		       "granted=%s (global-pid=%u) task={ pid=%u ppid=%u "
		       "uid=%u gid=%u euid=%u egid=%u suid=%u sgid=%u "
		       "fsuid=%u fsgid=%u type%s=execute_handler }",
		       stamp.year, stamp.month, stamp.day, stamp.hour,
		       stamp.min, stamp.sec, r->profile, ccs_mode[r->mode],
		       ccs_yesno(r->granted), gpid, ccs_sys_getpid(),
		       ccs_sys_getppid(), current_uid(), current_gid(),
		       current_euid(), current_egid(), current_suid(),
		       current_sgid(), current_fsuid(), current_fsgid(),
		       ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER ? "" : "!");
	if (!obj)
		goto no_obj_info;
	if (!obj->validate_done) {
		ccs_get_attributes(obj);
		obj->validate_done = true;
	}
	for (i = 0; i < CCS_MAX_PATH_STAT; i++) {
		struct ccs_mini_stat *stat;
		unsigned int dev;
		mode_t mode;
		if (!obj->stat_valid[i])
			continue;
		stat = &obj->stat[i];
		dev = stat->dev;
		mode = stat->mode;
		if (i & 1) {
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" path%u.parent={ uid=%u gid=%u "
					"ino=%lu perm=0%o }", (i >> 1) + 1,
					stat->uid, stat->gid, (unsigned long)
					stat->ino, stat->mode & S_IALLUGO);
			continue;
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path%u={ uid=%u gid=%u ino=%lu major=%u"
				" minor=%u perm=0%o type=%s", (i >> 1) + 1,
				stat->uid, stat->gid, (unsigned long)
				stat->ino, MAJOR(dev), MINOR(dev),
				mode & S_IALLUGO, ccs_filetype(mode));
		if (S_ISCHR(mode) || S_ISBLK(mode)) {
			dev = stat->rdev;
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" dev_major=%u dev_minor=%u",
					MAJOR(dev), MINOR(dev));
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos, " }");
	}
no_obj_info:
	if (pos < ccs_buffer_len - 1)
		return buffer;
	kfree(buffer);
	return NULL;
}

/**
 * ccs_init_log - Allocate buffer for audit logs.
 *
 * @r:    Pointer to "struct ccs_request_info".
 * @len:  Buffer size needed for @fmt and @args.
 * @fmt:  The printf()'s format string.
 * @args: va_list structure for @fmt.
 *
 * Returns pointer to allocated memory.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_init_log(struct ccs_request_info *r, int len, const char *fmt,
		   va_list args)
{
	char *buf = NULL;
	char *bprm_info = NULL;
	char *realpath = NULL;
	const char *symlink = NULL;
	const char *header = NULL;
	int pos;
	const char *domainname = ccs_current_domain()->domainname->name;
	header = ccs_print_header(r);
	if (!header)
		return NULL;
	/* +10 is for '\n' etc. and '\0'. */
	len += strlen(domainname) + strlen(header) + 10;
	if (r->ee) {
		struct file *file = r->ee->bprm->file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		struct path path = { file->f_vfsmnt, file->f_dentry };
		realpath = ccs_realpath_from_path(&path);
#else
		realpath = ccs_realpath_from_path(&file->f_path);
#endif
		bprm_info = ccs_print_bprm(r->ee->bprm, &r->ee->dump);
		if (!realpath || !bprm_info)
			goto out;
		/* +80 is for " exec={ realpath=\"%s\" argc=%d envc=%d %s }" */
		len += strlen(realpath) + 80 + strlen(bprm_info);
	} else if (r->obj && r->obj->symlink_target) {
		symlink = r->obj->symlink_target->name;
		/* +18 is for " symlink.target=\"%s\"" */
		len += 18 + strlen(symlink);
	}
	len = ccs_round2(len);
	buf = kzalloc(len, CCS_GFP_FLAGS);
	if (!buf)
		goto out;
	len--;
	pos = snprintf(buf, len, "%s", header);
	if (realpath) {
		struct linux_binprm *bprm = r->ee->bprm;
		pos += snprintf(buf + pos, len - pos,
				" exec={ realpath=\"%s\" argc=%d envc=%d %s }",
				realpath, bprm->argc, bprm->envc, bprm_info);
	} else if (symlink)
		pos += snprintf(buf + pos, len - pos, " symlink.target=\"%s\"",
				symlink);
	pos += snprintf(buf + pos, len - pos, "\n%s\n", domainname);
	vsnprintf(buf + pos, len - pos, fmt, args);
out:
	kfree(realpath);
	kfree(bprm_info);
	kfree(header);
	return buf;
}

/**
 * ccs_transition_failed - Print waning message and send signal when domain transition failed.
 *
 * @domainname: Name of domain to transit.
 *
 * Returns nothing.
 *
 * Note that if current->pid == 1, sending SIGKILL won't work.
 */
void ccs_transition_failed(const char *domainname)
{
	printk(KERN_WARNING
	       "ERROR: Unable to transit to '%s' domain.\n", domainname);
	force_sig(SIGKILL, current);
}

/**
 * ccs_update_task_domain - Update task's domain.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns nothing.
 *
 * The task will retry as hard as possible. But if domain transition failed,
 * the task will be killed by SIGKILL.
 */
static void ccs_update_task_domain(struct ccs_request_info *r)
{
	char *buf;
	const char *cp;
	const struct ccs_acl_info *acl = r->matched_acl;
	r->matched_acl = NULL;
	if (!acl || !acl->cond || !acl->cond->transit)
		return;
	while (1) {
		buf = kzalloc(CCS_EXEC_TMPSIZE, CCS_GFP_FLAGS);
		if (buf)
			break;
		ssleep(1);
		if (fatal_signal_pending(current))
			return;
	}
	cp = acl->cond->transit->name;
	if (*cp == '/')
		snprintf(buf, CCS_EXEC_TMPSIZE - 1, "%s %s",
			 ccs_current_domain()->domainname->name, cp);
	else
		strncpy(buf, cp, CCS_EXEC_TMPSIZE - 1);
	if (!ccs_assign_domain(buf, true))
		ccs_transition_failed(buf);
	kfree(buf);
}

/* Wait queue for /proc/ccs/audit. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_log_wait);

/* Structure for audit log. */
struct ccs_log {
	struct list_head list;
	char *log;
	int size;
};

/* The list for "struct ccs_log". */
static LIST_HEAD(ccs_log);

/* Lock for "struct list_head ccs_log". */
static DEFINE_SPINLOCK(ccs_log_lock);

/* Length of "stuct list_head ccs_log". */
static unsigned int ccs_log_count;

/**
 * ccs_get_audit - Get audit mode.
 *
 * @profile:     Profile number.
 * @index:       Index number of functionality.
 * @matched_acl: Pointer to "struct ccs_acl_info". Maybe NULL.
 * @is_granted:  True if granted log, false otherwise.
 *
 * Returns true if this request should be audited, false otherwise.
 */
static bool ccs_get_audit(const u8 profile, const u8 index,
			  const struct ccs_acl_info *matched_acl,
			  const bool is_granted)
{
	u8 mode;
	const u8 category = ccs_index2category[index] + CCS_MAX_MAC_INDEX;
	struct ccs_profile *p;
	if (!ccs_policy_loaded)
		return false;
	p = ccs_profile(profile);
	if (ccs_log_count >= p->pref[CCS_PREF_MAX_AUDIT_LOG])
		return false;
	if (is_granted && matched_acl && matched_acl->cond &&
	    matched_acl->cond->grant_log != CCS_GRANTLOG_AUTO)
		return matched_acl->cond->grant_log == CCS_GRANTLOG_YES;
	mode = p->config[index];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = p->config[category];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = p->default_config;
	if (is_granted)
		return mode & CCS_CONFIG_WANT_GRANT_LOG;
	return mode & CCS_CONFIG_WANT_REJECT_LOG;
}

/**
 * ccs_write_log2 - Write an audit log.
 *
 * @r:    Pointer to "struct ccs_request_info".
 * @len:  Buffer size needed for @fmt and @args.
 * @fmt:  The printf()'s format string.
 * @args: va_list structure for @fmt.
 *
 * Returns nothing.
 */
void ccs_write_log2(struct ccs_request_info *r, int len, const char *fmt,
		    va_list args)
{
	char *buf;
	struct ccs_log *entry;
	bool quota_exceeded = false;
	if (!ccs_get_audit(r->profile, r->type, r->matched_acl, r->granted))
		goto out;
	buf = ccs_init_log(r, len, fmt, args);
	if (!buf)
		goto out;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (!entry) {
		kfree(buf);
		goto out;
	}
	entry->log = buf;
	len = ccs_round2(strlen(buf) + 1);
	/*
	 * The entry->size is used for memory quota checks.
	 * Don't go beyond strlen(entry->log).
	 */
	entry->size = len + ccs_round2(sizeof(*entry));
	spin_lock(&ccs_log_lock);
	if (ccs_memory_quota[CCS_MEMORY_AUDIT] &&
	    ccs_memory_used[CCS_MEMORY_AUDIT] + entry->size >=
	    ccs_memory_quota[CCS_MEMORY_AUDIT]) {
		quota_exceeded = true;
	} else {
		ccs_memory_used[CCS_MEMORY_AUDIT] += entry->size;
		list_add_tail(&entry->list, &ccs_log);
		ccs_log_count++;
	}
	spin_unlock(&ccs_log_lock);
	if (quota_exceeded) {
		kfree(buf);
		kfree(entry);
		goto out;
	}
	wake_up(&ccs_log_wait);
out:
	ccs_update_task_domain(r);
}

/**
 * ccs_write_log - Write an audit log.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
void ccs_write_log(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int len;
	va_start(args, fmt);
	len = vsnprintf((char *) &len, 1, fmt, args) + 1;
	va_end(args);
	va_start(args, fmt);
	ccs_write_log2(r, len, fmt, args);
	va_end(args);
}

/**
 * ccs_read_log - Read an audit log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
void ccs_read_log(struct ccs_io_buffer *head)
{
	struct ccs_log *ptr = NULL;
	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&ccs_log_lock);
	if (!list_empty(&ccs_log)) {
		ptr = list_entry(ccs_log.next, typeof(*ptr), list);
		list_del(&ptr->list);
		ccs_log_count--;
		ccs_memory_used[CCS_MEMORY_AUDIT] -= ptr->size;
	}
	spin_unlock(&ccs_log_lock);
	if (ptr) {
		head->read_buf = ptr->log;
		head->r.w[head->r.w_pos++] = head->read_buf;
		kfree(ptr);
	}
}

/**
 * ccs_poll_log - Wait for an audit log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read an audit log.
 */
int ccs_poll_log(struct file *file, poll_table *wait)
{
	if (ccs_log_count)
		return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_log_wait, wait);
	if (ccs_log_count)
		return POLLIN | POLLRDNORM;
	return 0;
}
