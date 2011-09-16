/*
 * security/ccsecurity/policy_io.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3-pre   2011/09/16
 */

#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * __wait_event_interruptible_timeout - Sleep until a condition gets true or a timeout elapses.
 *
 * @wq:        The waitqueue to wait on.
 * @condition: A C expression for the event to wait for.
 * @ret:       Timeout, in jiffies.
 *
 * Returns 0 if the @timeout elapsed, -ERESTARTSYS if it was interrupted by a
 * signal, and the remaining jiffies otherwise if the condition evaluated to
 * true before the timeout elapsed.
 *
 * This is for compatibility with older kernels.
 */
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

/**
 * wait_event_interruptible_timeout - Sleep until a condition gets true or a timeout elapses.
 *
 * @wq:        The waitqueue to wait on.
 * @condition: A C expression for the event to wait for.
 * @timeout:   Timeout, in jiffies.
 *
 * Returns 0 if the @timeout elapsed, -ERESTARTSYS if it was interrupted by a
 * signal, and the remaining jiffies otherwise if the condition evaluated to
 * true before the timeout elapsed.
 *
 * This is for compatibility with older kernels.
 */
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#endif

/**
 * list_for_each_cookie - iterate over a list with cookie.
 *
 * @pos:  Pointer to "struct list_head".
 * @head: Pointer to "struct list_head".
 */
#define list_for_each_cookie(pos, head)					\
	for (pos = pos ? pos : srcu_dereference((head)->next, &ccs_ss); \
	     pos != (head); pos = srcu_dereference(pos->next, &ccs_ss))

/* String table for operation mode. */
const char * const ccs_mode[CCS_CONFIG_MAX_MODE] = {
	[CCS_CONFIG_DISABLED]   = "disabled",
	[CCS_CONFIG_LEARNING]   = "learning",
	[CCS_CONFIG_PERMISSIVE] = "permissive",
	[CCS_CONFIG_ENFORCING]  = "enforcing"
};

/* String table for /proc/ccs/profile interface. */
const char * const ccs_mac_keywords[CCS_MAX_MAC_INDEX
				    + CCS_MAX_MAC_CATEGORY_INDEX] = {
	/* CONFIG::file group */
	[CCS_MAC_FILE_EXECUTE]    = "execute",
	[CCS_MAC_FILE_OPEN]       = "open",
	[CCS_MAC_FILE_CREATE]     = "create",
	[CCS_MAC_FILE_UNLINK]     = "unlink",
	[CCS_MAC_FILE_GETATTR]    = "getattr",
	[CCS_MAC_FILE_MKDIR]      = "mkdir",
	[CCS_MAC_FILE_RMDIR]      = "rmdir",
	[CCS_MAC_FILE_MKFIFO]     = "mkfifo",
	[CCS_MAC_FILE_MKSOCK]     = "mksock",
	[CCS_MAC_FILE_TRUNCATE]   = "truncate",
	[CCS_MAC_FILE_SYMLINK]    = "symlink",
	[CCS_MAC_FILE_MKBLOCK]    = "mkblock",
	[CCS_MAC_FILE_MKCHAR]     = "mkchar",
	[CCS_MAC_FILE_LINK]       = "link",
	[CCS_MAC_FILE_RENAME]     = "rename",
	[CCS_MAC_FILE_CHMOD]      = "chmod",
	[CCS_MAC_FILE_CHOWN]      = "chown",
	[CCS_MAC_FILE_CHGRP]      = "chgrp",
	[CCS_MAC_FILE_IOCTL]      = "ioctl",
	[CCS_MAC_FILE_CHROOT]     = "chroot",
	[CCS_MAC_FILE_MOUNT]      = "mount",
	[CCS_MAC_FILE_UMOUNT]     = "unmount",
	[CCS_MAC_FILE_PIVOT_ROOT] = "pivot_root",
	/* CONFIG::misc group */
	[CCS_MAC_ENVIRON] = "env",
	/* CONFIG::network group */
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = "inet_stream_bind",
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = "inet_stream_listen",
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = "inet_stream_connect",
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = "inet_stream_accept",
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = "inet_dgram_bind",
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = "inet_dgram_send",
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = "inet_dgram_recv",
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = "inet_raw_bind",
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = "inet_raw_send",
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = "inet_raw_recv",
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = "unix_stream_bind",
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = "unix_stream_listen",
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = "unix_stream_connect",
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = "unix_stream_accept",
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = "unix_dgram_bind",
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = "unix_dgram_send",
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = "unix_dgram_recv",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = "unix_seqpacket_bind",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = "unix_seqpacket_listen",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = "unix_seqpacket_connect",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = "unix_seqpacket_accept",
	/* CONFIG::ipc group */
	[CCS_MAC_SIGNAL] = "signal",
	/* CONFIG::capability group */
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = "use_route",
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = "use_packet",
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = "SYS_REBOOT",
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = "SYS_VHANGUP",
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = "SYS_TIME",
	[CCS_MAC_CAPABILITY_SYS_NICE]          = "SYS_NICE",
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = "SYS_SETHOSTNAME",
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = "use_kernel_module",
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = "SYS_KEXEC_LOAD",
	[CCS_MAC_CAPABILITY_SYS_PTRACE]        = "SYS_PTRACE",
	/* CONFIG group */
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_FILE]       = "file",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_NETWORK]    = "network",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_MISC]       = "misc",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_IPC]        = "ipc",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for path operation. */
const char * const ccs_path_keyword[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_EXECUTE]    = "execute",
	[CCS_TYPE_READ]       = "read",
	[CCS_TYPE_WRITE]      = "write",
	[CCS_TYPE_APPEND]     = "append",
	[CCS_TYPE_UNLINK]     = "unlink",
	[CCS_TYPE_GETATTR]    = "getattr",
	[CCS_TYPE_RMDIR]      = "rmdir",
	[CCS_TYPE_TRUNCATE]   = "truncate",
	[CCS_TYPE_SYMLINK]    = "symlink",
	[CCS_TYPE_CHROOT]     = "chroot",
	[CCS_TYPE_UMOUNT]     = "unmount",
};

/* String table for socket's operation. */
const char * const ccs_socket_keyword[CCS_MAX_NETWORK_OPERATION] = {
	[CCS_NETWORK_BIND]    = "bind",
	[CCS_NETWORK_LISTEN]  = "listen",
	[CCS_NETWORK_CONNECT] = "connect",
	[CCS_NETWORK_ACCEPT]  = "accept",
	[CCS_NETWORK_SEND]    = "send",
	[CCS_NETWORK_RECV]    = "recv",
};

/* String table for categories. */
static const char * const ccs_category_keywords[CCS_MAX_MAC_CATEGORY_INDEX] = {
	[CCS_MAC_CATEGORY_FILE]       = "file",
	[CCS_MAC_CATEGORY_NETWORK]    = "network",
	[CCS_MAC_CATEGORY_MISC]       = "misc",
	[CCS_MAC_CATEGORY_IPC]        = "ipc",
	[CCS_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for conditions. */
const char * const ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD] = {
	[CCS_TASK_UID]             = "task.uid",
	[CCS_TASK_EUID]            = "task.euid",
	[CCS_TASK_SUID]            = "task.suid",
	[CCS_TASK_FSUID]           = "task.fsuid",
	[CCS_TASK_GID]             = "task.gid",
	[CCS_TASK_EGID]            = "task.egid",
	[CCS_TASK_SGID]            = "task.sgid",
	[CCS_TASK_FSGID]           = "task.fsgid",
	[CCS_TASK_PID]             = "task.pid",
	[CCS_TASK_PPID]            = "task.ppid",
	[CCS_EXEC_ARGC]            = "exec.argc",
	[CCS_EXEC_ENVC]            = "exec.envc",
	[CCS_TYPE_IS_SOCKET]       = "socket",
	[CCS_TYPE_IS_SYMLINK]      = "symlink",
	[CCS_TYPE_IS_FILE]         = "file",
	[CCS_TYPE_IS_BLOCK_DEV]    = "block",
	[CCS_TYPE_IS_DIRECTORY]    = "directory",
	[CCS_TYPE_IS_CHAR_DEV]     = "char",
	[CCS_TYPE_IS_FIFO]         = "fifo",
	[CCS_MODE_SETUID]          = "setuid",
	[CCS_MODE_SETGID]          = "setgid",
	[CCS_MODE_STICKY]          = "sticky",
	[CCS_MODE_OWNER_READ]      = "owner_read",
	[CCS_MODE_OWNER_WRITE]     = "owner_write",
	[CCS_MODE_OWNER_EXECUTE]   = "owner_execute",
	[CCS_MODE_GROUP_READ]      = "group_read",
	[CCS_MODE_GROUP_WRITE]     = "group_write",
	[CCS_MODE_GROUP_EXECUTE]   = "group_execute",
	[CCS_MODE_OTHERS_READ]     = "others_read",
	[CCS_MODE_OTHERS_WRITE]    = "others_write",
	[CCS_MODE_OTHERS_EXECUTE]  = "others_execute",
	[CCS_TASK_TYPE]            = "task.type",
	[CCS_TASK_EXECUTE_HANDLER] = "execute_handler",
	[CCS_EXEC_REALPATH]        = "exec.realpath",
	[CCS_SYMLINK_TARGET]       = "symlink.target",
	[CCS_PATH1_UID]            = "path1.uid",
	[CCS_PATH1_GID]            = "path1.gid",
	[CCS_PATH1_INO]            = "path1.ino",
	[CCS_PATH1_MAJOR]          = "path1.major",
	[CCS_PATH1_MINOR]          = "path1.minor",
	[CCS_PATH1_PERM]           = "path1.perm",
	[CCS_PATH1_TYPE]           = "path1.type",
	[CCS_PATH1_DEV_MAJOR]      = "path1.dev_major",
	[CCS_PATH1_DEV_MINOR]      = "path1.dev_minor",
	[CCS_PATH2_UID]            = "path2.uid",
	[CCS_PATH2_GID]            = "path2.gid",
	[CCS_PATH2_INO]            = "path2.ino",
	[CCS_PATH2_MAJOR]          = "path2.major",
	[CCS_PATH2_MINOR]          = "path2.minor",
	[CCS_PATH2_PERM]           = "path2.perm",
	[CCS_PATH2_TYPE]           = "path2.type",
	[CCS_PATH2_DEV_MAJOR]      = "path2.dev_major",
	[CCS_PATH2_DEV_MINOR]      = "path2.dev_minor",
	[CCS_PATH1_PARENT_UID]     = "path1.parent.uid",
	[CCS_PATH1_PARENT_GID]     = "path1.parent.gid",
	[CCS_PATH1_PARENT_INO]     = "path1.parent.ino",
	[CCS_PATH1_PARENT_PERM]    = "path1.parent.perm",
	[CCS_PATH2_PARENT_UID]     = "path2.parent.uid",
	[CCS_PATH2_PARENT_GID]     = "path2.parent.gid",
	[CCS_PATH2_PARENT_INO]     = "path2.parent.ino",
	[CCS_PATH2_PARENT_PERM]    = "path2.parent.perm",
};

/* String table for PREFERENCE keyword. */
static const char * const ccs_pref_keywords[CCS_MAX_PREF] = {
	[CCS_PREF_MAX_AUDIT_LOG]      = "max_audit_log",
	[CCS_PREF_MAX_LEARNING_ENTRY] = "max_learning_entry",
	[CCS_PREF_ENFORCING_PENALTY]  = "enforcing_penalty",
};

/* Permit policy management by non-root user? */
static bool ccs_manage_by_non_root;

/**
 * ccs_yesno - Return "yes" or "no".
 *
 * @value: Bool value.
 *
 * Returns "yes" if @value is not 0, "no" otherwise.
 */
const char *ccs_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

/* Prototype for ccs_addprintf(). */
static void ccs_addprintf(char *buffer, int len, const char *fmt, ...)
	__attribute__ ((format(printf, 3, 4)));

/**
 * ccs_addprintf - strncat()-like-snprintf().
 *
 * @buffer: Buffer to write to. Must be '\0'-terminated.
 * @len:    Size of @buffer.
 * @fmt:    The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
static void ccs_addprintf(char *buffer, int len, const char *fmt, ...)
{
	va_list args;
	const int pos = strlen(buffer);
	va_start(args, fmt);
	vsnprintf(buffer + pos, len - pos - 1, fmt, args);
	va_end(args);
}

/**
 * ccs_flush - Flush queued string to userspace's buffer.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true if all data was flushed, false otherwise.
 */
static bool ccs_flush(struct ccs_io_buffer *head)
{
	while (head->r.w_pos) {
		const char *w = head->r.w[0];
		size_t len = strlen(w);
		if (len) {
			if (len > head->read_user_buf_avail)
				len = head->read_user_buf_avail;
			if (!len)
				return false;
			if (copy_to_user(head->read_user_buf, w, len))
				return false;
			head->read_user_buf_avail -= len;
			head->read_user_buf += len;
			w += len;
		}
		head->r.w[0] = w;
		if (*w)
			return false;
		/* Add '\0' for audit logs and query. */
		if (head->type == CCS_AUDIT || head->type == CCS_QUERY) {
			if (!head->read_user_buf_avail ||
			    copy_to_user(head->read_user_buf, "", 1))
				return false;
			head->read_user_buf_avail--;
			head->read_user_buf++;
		}
		head->r.w_pos--;
		for (len = 0; len < head->r.w_pos; len++)
			head->r.w[len] = head->r.w[len + 1];
	}
	head->r.avail = 0;
	return true;
}

/**
 * ccs_set_string - Queue string to "struct ccs_io_buffer" structure.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @string: String to print.
 *
 * Returns nothing.
 *
 * Note that @string has to be kept valid until @head is kfree()d.
 * This means that char[] allocated on stack memory cannot be passed to
 * this function. Use ccs_io_printf() for char[] allocated on stack memory.
 */
static void ccs_set_string(struct ccs_io_buffer *head, const char *string)
{
	if (head->r.w_pos < CCS_MAX_IO_READ_QUEUE) {
		head->r.w[head->r.w_pos++] = string;
		ccs_flush(head);
	} else
		printk(KERN_WARNING "Too many words in a line.\n");
}

/* Prototype for ccs_io_printf(). */
static void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));

/**
 * ccs_io_printf - printf() to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
static void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	size_t len;
	size_t pos = head->r.avail;
	int size = head->readbuf_size - pos;
	if (size <= 0)
		return;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args) + 1;
	va_end(args);
	if (pos + len >= head->readbuf_size) {
		printk(KERN_WARNING "Too many words in a line.\n");
		return;
	}
	head->r.avail += len;
	ccs_set_string(head, head->read_buf + pos);
}

/**
 * ccs_set_space - Put a space to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_set_space(struct ccs_io_buffer *head)
{
	ccs_set_string(head, " ");
}

/**
 * ccs_set_lf - Put a line feed to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static bool ccs_set_lf(struct ccs_io_buffer *head)
{
	ccs_set_string(head, "\n");
	return !head->r.w_pos;
}

/**
 * ccs_set_slash - Put a shash to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_set_slash(struct ccs_io_buffer *head)
{
	ccs_set_string(head, "/");
}

/* List of namespaces. */
LIST_HEAD(ccs_namespace_list);
/* True if namespace other than ccs_kernel_namespace is defined. */
static bool ccs_namespace_enabled;

/**
 * ccs_init_policy_namespace - Initialize namespace.
 *
 * @ns: Pointer to "struct ccs_policy_namespace".
 *
 * Returns nothing.
 */
void ccs_init_policy_namespace(struct ccs_policy_namespace *ns)
{
	unsigned int idx;
	for (idx = 0; idx < CCS_MAX_ACL_GROUPS; idx++)
		INIT_LIST_HEAD(&ns->acl_group[idx]);
	for (idx = 0; idx < CCS_MAX_GROUP; idx++)
		INIT_LIST_HEAD(&ns->group_list[idx]);
	for (idx = 0; idx < CCS_MAX_POLICY; idx++)
		INIT_LIST_HEAD(&ns->policy_list[idx]);
	ns->profile_version = 20100903;
	ccs_namespace_enabled = !list_empty(&ccs_namespace_list);
	list_add_tail_rcu(&ns->namespace_list, &ccs_namespace_list);
}

/**
 * ccs_print_namespace - Print namespace header.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_print_namespace(struct ccs_io_buffer *head)
{
	if (!ccs_namespace_enabled)
		return;
	ccs_set_string(head,
		       container_of(head->r.ns, struct ccs_policy_namespace,
				    namespace_list)->name);
	ccs_set_space(head);
}

/**
 * ccs_assign_profile - Create a new profile.
 *
 * @ns:      Pointer to "struct ccs_policy_namespace".
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct ccs_profile" on success, NULL otherwise.
 */
static struct ccs_profile *ccs_assign_profile(struct ccs_policy_namespace *ns,
					      const unsigned int profile)
{
	struct ccs_profile *ptr;
	struct ccs_profile *entry;
	if (profile >= CCS_MAX_PROFILES)
		return NULL;
	ptr = ns->profile_ptr[profile];
	if (ptr)
		return ptr;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	ptr = ns->profile_ptr[profile];
	if (!ptr && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		ptr->default_config = CCS_CONFIG_DISABLED |
			CCS_CONFIG_WANT_GRANT_LOG | CCS_CONFIG_WANT_REJECT_LOG;
		memset(ptr->config, CCS_CONFIG_USE_DEFAULT,
		       sizeof(ptr->config));
		ptr->pref[CCS_PREF_MAX_AUDIT_LOG] =
			CONFIG_CCSECURITY_MAX_AUDIT_LOG;
		ptr->pref[CCS_PREF_MAX_LEARNING_ENTRY] =
			CONFIG_CCSECURITY_MAX_ACCEPT_ENTRY;
		mb(); /* Avoid out-of-order execution. */
		ns->profile_ptr[profile] = ptr;
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
out:
	kfree(entry);
	return ptr;
}

/**
 * ccs_check_profile - Check all profiles currently assigned to domains are defined.
 *
 * Returns nothing.
 */
static void ccs_check_profile(void)
{
	struct ccs_domain_info *domain;
	const int idx = ccs_read_lock();
	ccs_policy_loaded = true;
	printk(KERN_INFO "CCSecurity: 1.8.3-pre   2011/09/16\n");
	list_for_each_entry_srcu(domain, &ccs_domain_list, list, &ccs_ss) {
		const u8 profile = domain->profile;
		const struct ccs_policy_namespace *ns = domain->ns;
		if (ns->profile_version != 20100903)
			printk(KERN_ERR
			       "Profile version %u is not supported.\n",
			       ns->profile_version);
		else if (!ns->profile_ptr[profile])
			printk(KERN_ERR
			       "Profile %u (used by '%s') is not defined.\n",
			       profile, domain->domainname->name);
		else
			continue;
		printk(KERN_ERR
		       "Userland tools for TOMOYO 1.8 must be installed and "
		       "policy must be initialized.\n");
		printk(KERN_ERR "Please see http://tomoyo.sourceforge.jp/1.8/ "
		       "for more information.\n");
		panic("STOP!");
	}
	ccs_read_unlock(idx);
	printk(KERN_INFO "Mandatory Access Control activated.\n");
}

/**
 * ccs_profile - Find a profile.
 *
 * @profile: Profile number to find.
 *
 * Returns pointer to "struct ccs_profile".
 */
struct ccs_profile *ccs_profile(const u8 profile)
{
	static struct ccs_profile ccs_null_profile;
	struct ccs_profile *ptr = ccs_current_namespace()->
		profile_ptr[profile];
	if (!ptr)
		ptr = &ccs_null_profile;
	return ptr;
}

/**
 * ccs_find_yesno - Find values for specified keyword.
 *
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns 1 if "@find=yes" was found, 0 if "@find=no" was found, -1 otherwise.
 */
static s8 ccs_find_yesno(const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp) {
		cp += strlen(find);
		if (!strncmp(cp, "=yes", 4))
			return 1;
		else if (!strncmp(cp, "=no", 3))
			return 0;
	}
	return -1;
}

/**
 * ccs_set_uint - Set value for specified preference.
 *
 * @i:      Pointer to "unsigned int".
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns nothing.
 */
static void ccs_set_uint(unsigned int *i, const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp)
		sscanf(cp + strlen(find), "=%u", i);
}

/**
 * ccs_set_mode - Set mode for specified profile.
 *
 * @name:    Name of functionality.
 * @value:   Mode for @name.
 * @profile: Pointer to "struct ccs_profile".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_set_mode(char *name, const char *value,
			struct ccs_profile *profile)
{
	u8 i;
	u8 config;
	if (!strcmp(name, "CONFIG")) {
		i = CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX;
		config = profile->default_config;
	} else if (ccs_str_starts(&name, "CONFIG::")) {
		config = 0;
		for (i = 0; i < CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX;
		     i++) {
			int len = 0;
			if (i < CCS_MAX_MAC_INDEX) {
				const u8 c = ccs_index2category[i];
				const char *category =
					ccs_category_keywords[c];
				len = strlen(category);
				if (strncmp(name, category, len) ||
				    name[len++] != ':' || name[len++] != ':')
					continue;
			}
			if (strcmp(name + len, ccs_mac_keywords[i]))
				continue;
			config = profile->config[i];
			break;
		}
		if (i == CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (strstr(value, "use_default")) {
		config = CCS_CONFIG_USE_DEFAULT;
	} else {
		u8 mode;
		for (mode = 0; mode < CCS_CONFIG_MAX_MODE; mode++)
			if (strstr(value, ccs_mode[mode]))
				/*
				 * Update lower 3 bits in order to distinguish
				 * 'config' from 'CCS_CONFIG_USE_DEAFULT'.
				 */
				config = (config & ~7) | mode;
		if (config != CCS_CONFIG_USE_DEFAULT) {
			switch (ccs_find_yesno(value, "grant_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_GRANT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_GRANT_LOG;
				break;
			}
			switch (ccs_find_yesno(value, "reject_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_REJECT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_REJECT_LOG;
				break;
			}
		}
	}
	if (i < CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX)
		profile->config[i] = config;
	else if (config != CCS_CONFIG_USE_DEFAULT)
		profile->default_config = config;
	return 0;
}

/**
 * ccs_write_profile - Write profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int i;
	char *cp;
	struct ccs_profile *profile;
	if (sscanf(data, "PROFILE_VERSION=%u", &head->w.ns->profile_version)
	    == 1)
		return 0;
	i = simple_strtoul(data, &cp, 10);
	if (*cp != '-')
		return -EINVAL;
	data = cp + 1;
	profile = ccs_assign_profile(head->w.ns, i);
	if (!profile)
		return -EINVAL;
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	if (!strcmp(data, "COMMENT")) {
		static DEFINE_SPINLOCK(lock);
		const struct ccs_path_info *new_comment = ccs_get_name(cp);
		const struct ccs_path_info *old_comment;
		if (!new_comment)
			return -ENOMEM;
		spin_lock(&lock);
		old_comment = profile->comment;
		profile->comment = new_comment;
		spin_unlock(&lock);
		ccs_put_name(old_comment);
		return 0;
	}
	if (!strcmp(data, "PREFERENCE")) {
		for (i = 0; i < CCS_MAX_PREF; i++)
			ccs_set_uint(&profile->pref[i], cp,
				     ccs_pref_keywords[i]);
		return 0;
	}
	return ccs_set_mode(data, cp, profile);
}

/**
 * ccs_print_config - Print mode for specified functionality.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @config: Mode for that functionality.
 *
 * Returns nothing.
 *
 * Caller prints functionality's name.
 */
static void ccs_print_config(struct ccs_io_buffer *head, const u8 config)
{
	ccs_io_printf(head, "={ mode=%s grant_log=%s reject_log=%s }\n",
		      ccs_mode[config & 3],
		      ccs_yesno(config & CCS_CONFIG_WANT_GRANT_LOG),
		      ccs_yesno(config & CCS_CONFIG_WANT_REJECT_LOG));
}

/**
 * ccs_read_profile - Read profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_profile(struct ccs_io_buffer *head)
{
	u8 index;
	struct ccs_policy_namespace *ns = container_of(head->r.ns, typeof(*ns),
						       namespace_list);
	const struct ccs_profile *profile;
	if (head->r.eof)
		return;
next:
	index = head->r.index;
	profile = ns->profile_ptr[index];
	switch (head->r.step) {
	case 0:
		ccs_print_namespace(head);
		ccs_io_printf(head, "PROFILE_VERSION=%u\n",
			      ns->profile_version);
		head->r.step++;
		break;
	case 1:
		for ( ; head->r.index < CCS_MAX_PROFILES; head->r.index++)
			if (ns->profile_ptr[head->r.index])
				break;
		if (head->r.index == CCS_MAX_PROFILES) {
			head->r.eof = true;
			return;
		}
		head->r.step++;
		break;
	case 2:
		{
			u8 i;
			const struct ccs_path_info *comment = profile->comment;
			ccs_print_namespace(head);
			ccs_io_printf(head, "%u-COMMENT=", index);
			ccs_set_string(head, comment ? comment->name : "");
			ccs_set_lf(head);
			ccs_print_namespace(head);
			ccs_io_printf(head, "%u-PREFERENCE={ ", index);
			for (i = 0; i < CCS_MAX_PREF; i++)
				ccs_io_printf(head, "%s=%u ",
					      ccs_pref_keywords[i],
					      profile->pref[i]);
			ccs_set_string(head, "}\n");
			head->r.step++;
		}
		break;
	case 3:
		{
			ccs_print_namespace(head);
			ccs_io_printf(head, "%u-%s", index, "CONFIG");
			ccs_print_config(head, profile->default_config);
			head->r.bit = 0;
			head->r.step++;
		}
		break;
	case 4:
		for ( ; head->r.bit < CCS_MAX_MAC_INDEX
			      + CCS_MAX_MAC_CATEGORY_INDEX; head->r.bit++) {
			const u8 i = head->r.bit;
			const u8 config = profile->config[i];
			if (config == CCS_CONFIG_USE_DEFAULT)
				continue;
			ccs_print_namespace(head);
			if (i < CCS_MAX_MAC_INDEX)
				ccs_io_printf(head, "%u-CONFIG::%s::%s", index,
					      ccs_category_keywords
					      [ccs_index2category[i]],
					      ccs_mac_keywords[i]);
			else
				ccs_io_printf(head, "%u-CONFIG::%s", index,
					      ccs_mac_keywords[i]);
			ccs_print_config(head, config);
			head->r.bit++;
			break;
		}
		if (head->r.bit == CCS_MAX_MAC_INDEX
		    + CCS_MAX_MAC_CATEGORY_INDEX) {
			head->r.index++;
			head->r.step = 1;
		}
		break;
	}
	if (ccs_flush(head))
		goto next;
}

/**
 * ccs_same_manager - Check for duplicated "struct ccs_manager" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_manager(const struct ccs_acl_head *a,
			     const struct ccs_acl_head *b)
{
	return container_of(a, struct ccs_manager, head)->manager
		== container_of(b, struct ccs_manager, head)->manager;
}

/**
 * ccs_update_manager_entry - Add a manager entry.
 *
 * @manager:   The path to manager or the domainnamme.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_manager_entry(const char *manager,
					   const bool is_delete)
{
	struct ccs_manager e = { };
	struct ccs_acl_param param = {
		/* .ns = &ccs_kernel_namespace, */
		.is_delete = is_delete,
		.list = &ccs_kernel_namespace.policy_list[CCS_ID_MANAGER],
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (ccs_domain_def(manager)) {
		if (!ccs_correct_domain(manager))
			return -EINVAL;
		e.is_domain = true;
	} else {
		if (!ccs_correct_path(manager))
			return -EINVAL;
	}
	e.manager = ccs_get_name(manager);
	if (e.manager) {
		error = ccs_update_policy(&e.head, sizeof(e), &param,
					  ccs_same_manager);
		ccs_put_name(e.manager);
	}
	return error;
}

/**
 * ccs_write_manager - Write manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_manager(struct ccs_io_buffer *head)
{
	const char *data = head->write_buf;
	if (!strcmp(data, "manage_by_non_root")) {
		ccs_manage_by_non_root = !head->w.is_delete;
		return 0;
	}
	return ccs_update_manager_entry(data, head->w.is_delete);
}

/**
 * ccs_read_manager - Read manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_manager(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	list_for_each_cookie(head->r.acl, &ccs_kernel_namespace.
			     policy_list[CCS_ID_MANAGER]) {
		struct ccs_manager *ptr =
			list_entry(head->r.acl, typeof(*ptr), head.list);
		if (ptr->head.is_deleted)
			continue;
		if (!ccs_flush(head))
			return;
		ccs_set_string(head, ptr->manager->name);
		ccs_set_lf(head);
	}
	head->r.eof = true;
}

/**
 * ccs_manager - Check whether the current process is a policy manager.
 *
 * Returns true if the current process is permitted to modify policy
 * via /proc/ccs/ interface.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_manager(void)
{
	struct ccs_manager *ptr;
	const char *exe;
	struct ccs_security *task = ccs_current_security();
	const struct ccs_path_info *domainname
		= ccs_current_domain()->domainname;
	bool found = false;
	if (!ccs_policy_loaded)
		return true;
	if (task->ccs_flags & CCS_TASK_IS_MANAGER)
		return true;
	if (!ccs_manage_by_non_root && (current_uid() || current_euid()))
		return false;
	exe = ccs_get_exe();
	list_for_each_entry_srcu(ptr, &ccs_kernel_namespace.
				 policy_list[CCS_ID_MANAGER], head.list,
				 &ccs_ss) {
		if (ptr->head.is_deleted)
			continue;
		if (ptr->is_domain) {
			if (ccs_pathcmp(domainname, ptr->manager))
				continue;
		} else {
			if (!exe || strcmp(exe, ptr->manager->name))
				continue;
		}
		/* Set manager flag. */
		task->ccs_flags |= CCS_TASK_IS_MANAGER;
		found = true;
		break;
	}
	if (!found) { /* Reduce error messages. */
		static pid_t ccs_last_pid;
		const pid_t pid = current->pid;
		if (ccs_last_pid != pid) {
			printk(KERN_WARNING "%s ( %s ) is not permitted to "
			       "update policies.\n", domainname->name, exe);
			ccs_last_pid = pid;
		}
	}
	kfree(exe);
	return found;
}

/**
 * ccs_select_domain - Parse select command.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_select_domain(struct ccs_io_buffer *head, const char *data)
{
	unsigned int pid;
	struct ccs_domain_info *domain = NULL;
	bool global_pid = false;
	if (strncmp(data, "select ", 7))
		return false;
	data += 7;
	if (sscanf(data, "pid=%u", &pid) == 1 ||
	    (global_pid = true, sscanf(data, "global-pid=%u", &pid) == 1)) {
		struct task_struct *p;
		ccs_tasklist_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		if (global_pid)
			p = ccsecurity_exports.find_task_by_pid_ns(pid,
							       &init_pid_ns);
		else
			p = ccsecurity_exports.find_task_by_vpid(pid);
#else
		p = find_task_by_pid(pid);
#endif
		if (p)
			domain = ccs_task_domain(p);
		ccs_tasklist_unlock();
	} else if (!strncmp(data, "domain=", 7)) {
		if (*(data + 7) == '<')
			domain = ccs_find_domain(data + 7);
	} else
		return false;
	head->w.domain = domain;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	memset(&head->r, 0, sizeof(head->r));
	head->r.print_this_domain_only = true;
	if (domain)
		head->r.domain = &domain->list;
	else
		head->r.eof = true;
	ccs_io_printf(head, "# select %s\n", data);
	if (domain && domain->is_deleted)
		ccs_set_string(head, "# This is a deleted domain.\n");
	return true;
}

/**
 * ccs_same_handler_acl - Check for duplicated "struct ccs_handler_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_handler_acl(const struct ccs_acl_info *a,
				 const struct ccs_acl_info *b)
{
	const struct ccs_handler_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_handler_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->handler == p2->handler;
}

/**
 * ccs_same_task_acl - Check for duplicated "struct ccs_task_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_task_acl(const struct ccs_acl_info *a,
			      const struct ccs_acl_info *b)
{
	const struct ccs_task_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_task_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->domainname == p2->domainname;
}

/**
 * ccs_write_task - Update task related list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_task(struct ccs_acl_param *param)
{
	int error;
	const bool is_auto = ccs_str_starts(&param->data,
					    "auto_domain_transition ");
	if (!is_auto && !ccs_str_starts(&param->data,
					"manual_domain_transition ")) {
		struct ccs_handler_acl e = { };
		char *handler;
		if (ccs_str_starts(&param->data, "auto_execute_handler "))
			e.head.type = CCS_TYPE_AUTO_EXECUTE_HANDLER;
		else if (ccs_str_starts(&param->data,
					"denied_execute_handler "))
			e.head.type = CCS_TYPE_DENIED_EXECUTE_HANDLER;
		else
			return -EINVAL;
		handler = ccs_read_token(param);
		if (!ccs_correct_path(handler))
			return -EINVAL;
		e.handler = ccs_get_name(handler);
		if (!e.handler)
			return -ENOMEM;
		if (e.handler->is_patterned)
			error = -EINVAL; /* No patterns allowed. */
		else
			error = ccs_update_domain(&e.head, sizeof(e), param,
						  ccs_same_handler_acl, NULL);
		ccs_put_name(e.handler);
	} else {
		struct ccs_task_acl e = {
			.head.type = is_auto ?
			CCS_TYPE_AUTO_TASK_ACL : CCS_TYPE_MANUAL_TASK_ACL,
			.domainname = ccs_get_domainname(param),
		};
		if (!e.domainname)
			error = -EINVAL;
		else
			error = ccs_update_domain(&e.head, sizeof(e), param,
						  ccs_same_task_acl, NULL);
		ccs_put_name(e.domainname);
	}
	return error;
}

/**
 * ccs_write_domain2 - Write domain policy.
 *
 * @ns:        Pointer to "struct ccs_policy_namespace".
 * @list:      Pointer to "struct list_head".
 * @data:      Policy to be interpreted.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_domain2(struct ccs_policy_namespace *ns,
			     struct list_head *list, char *data,
			     const bool is_delete)
{
	struct ccs_acl_param param = {
		.ns = ns,
		.list = list,
		.data = data,
		.is_delete = is_delete,
	};
	static const struct {
		const char *keyword;
		int (*write) (struct ccs_acl_param *);
	} ccs_callback[7] = {
		{ "file ", ccs_write_file },
		{ "network inet ", ccs_write_inet_network },
		{ "network unix ", ccs_write_unix_network },
		{ "misc ", ccs_write_misc },
		{ "capability ", ccs_write_capability },
		{ "ipc signal ", ccs_write_ipc },
		{ "task ", ccs_write_task },
	};
	u8 i;
	for (i = 0; i < ARRAY_SIZE(ccs_callback); i++) {
		if (!ccs_str_starts(&param.data, ccs_callback[i].keyword))
			continue;
		return ccs_callback[i].write(&param);
	}
	return -EINVAL;
}

/**
 * ccs_delete_domain - Delete a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns 0.
 */
static int ccs_delete_domain(char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return 0;
	/* Is there an active domain? */
	list_for_each_entry_srcu(domain, &ccs_domain_list, list, &ccs_ss) {
		/* Never delete ccs_kernel_domain. */
		if (domain == &ccs_kernel_domain)
			continue;
		if (domain->is_deleted ||
		    ccs_pathcmp(domain->domainname, &name))
			continue;
		domain->is_deleted = true;
		break;
	}
	mutex_unlock(&ccs_policy_lock);
	return 0;
}

/* String table for domain flags. */
const char * const ccs_dif[CCS_MAX_DOMAIN_INFO_FLAGS] = {
	[CCS_DIF_QUOTA_WARNED]      = "quota_exceeded\n",
	[CCS_DIF_TRANSITION_FAILED] = "transition_failed\n",
};

/**
 * ccs_write_domain - Write domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_domain(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct ccs_policy_namespace *ns;
	struct ccs_domain_info *domain = head->w.domain;
	const bool is_delete = head->w.is_delete;
	const bool is_select = !is_delete && ccs_str_starts(&data, "select ");
	unsigned int profile;
	if (*data == '<') {
		domain = NULL;
		if (is_delete)
			ccs_delete_domain(data);
		else if (is_select)
			domain = ccs_find_domain(data);
		else
			domain = ccs_assign_domain(data, false);
		head->w.domain = domain;
		return 0;
	}
	if (!domain)
		return -EINVAL;
	ns = domain->ns;
	if (sscanf(data, "use_profile %u\n", &profile) == 1
	    && profile < CCS_MAX_PROFILES) {
		if (!ccs_policy_loaded || ns->profile_ptr[(u8) profile])
			if (!is_delete)
				domain->profile = (u8) profile;
		return 0;
	}
	if (sscanf(data, "use_group %u\n", &profile) == 1
	    && profile < CCS_MAX_ACL_GROUPS) {
		if (!is_delete)
			domain->group = (u8) profile;
		return 0;
	}
	for (profile = 0; profile < CCS_MAX_DOMAIN_INFO_FLAGS; profile++) {
		const char *cp = ccs_dif[profile];
		if (strncmp(data, cp, strlen(cp) - 1))
			continue;
		domain->flags[profile] = !is_delete;
		return 0;
	}
	return ccs_write_domain2(ns, &domain->acl_info_list, data, is_delete);
}

/**
 * ccs_print_name_union - Print a ccs_name_union.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_name_union".
 *
 * Returns nothing.
 */
static void ccs_print_name_union(struct ccs_io_buffer *head,
				 const struct ccs_name_union *ptr)
{
	ccs_set_space(head);
	if (ptr->group) {
		ccs_set_string(head, "@");
		ccs_set_string(head, ptr->group->group_name->name);
	} else {
		ccs_set_string(head, ptr->filename->name);
	}
}

/**
 * ccs_print_name_union_quoted - Print a ccs_name_union with a quote.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_name_union".
 *
 * Returns nothing.
 */
static void ccs_print_name_union_quoted(struct ccs_io_buffer *head,
					const struct ccs_name_union *ptr)
{
	if (ptr->group) {
		ccs_set_string(head, "@");
		ccs_set_string(head, ptr->group->group_name->name);
	} else {
		ccs_set_string(head, "\"");
		ccs_set_string(head, ptr->filename->name);
		ccs_set_string(head, "\"");
	}
}

/**
 * ccs_print_number_union_nospace - Print a ccs_number_union without a space.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_number_union".
 *
 * Returns nothing.
 */
static void ccs_print_number_union_nospace(struct ccs_io_buffer *head,
					   const struct ccs_number_union *ptr)
{
	if (ptr->group) {
		ccs_set_string(head, "@");
		ccs_set_string(head, ptr->group->group_name->name);
	} else {
		int i;
		unsigned long min = ptr->values[0];
		const unsigned long max = ptr->values[1];
		u8 min_type = ptr->value_type[0];
		const u8 max_type = ptr->value_type[1];
		char buffer[128];
		buffer[0] = '\0';
		for (i = 0; i < 2; i++) {
			switch (min_type) {
			case CCS_VALUE_TYPE_HEXADECIMAL:
				ccs_addprintf(buffer, sizeof(buffer), "0x%lX",
					      min);
				break;
			case CCS_VALUE_TYPE_OCTAL:
				ccs_addprintf(buffer, sizeof(buffer), "0%lo",
					      min);
				break;
			default:
				ccs_addprintf(buffer, sizeof(buffer), "%lu",
					      min);
				break;
			}
			if (min == max && min_type == max_type)
				break;
			ccs_addprintf(buffer, sizeof(buffer), "-");
			min_type = max_type;
			min = max;
		}
		ccs_io_printf(head, "%s", buffer);
	}
}

/**
 * ccs_print_number_union - Print a ccs_number_union.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_number_union".
 *
 * Returns nothing.
 */
static void ccs_print_number_union(struct ccs_io_buffer *head,
				   const struct ccs_number_union *ptr)
{
	ccs_set_space(head);
	ccs_print_number_union_nospace(head, ptr);
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_condition(struct ccs_io_buffer *head,
				const struct ccs_condition *cond)
{
	switch (head->r.cond_step) {
	case 0:
		head->r.cond_index = 0;
		head->r.cond_step++;
		if (cond->transit && cond->exec_transit) {
			ccs_set_space(head);
			ccs_set_string(head, cond->transit->name);
		}
		/* fall through */
	case 1:
		{
			const u16 condc = cond->condc;
			const struct ccs_condition_element *condp =
				(typeof(condp)) (cond + 1);
			const struct ccs_number_union *numbers_p =
				(typeof(numbers_p)) (condp + condc);
			const struct ccs_name_union *names_p =
				(typeof(names_p))
				(numbers_p + cond->numbers_count);
			const struct ccs_argv *argv =
				(typeof(argv)) (names_p + cond->names_count);
			const struct ccs_envp *envp =
				(typeof(envp)) (argv + cond->argc);
			u16 skip;
			for (skip = 0; skip < head->r.cond_index; skip++) {
				const u8 left = condp->left;
				const u8 right = condp->right;
				condp++;
				switch (left) {
				case CCS_ARGV_ENTRY:
					argv++;
					continue;
				case CCS_ENVP_ENTRY:
					envp++;
					continue;
				case CCS_NUMBER_UNION:
					numbers_p++;
					break;
				}
				switch (right) {
				case CCS_NAME_UNION:
					names_p++;
					break;
				case CCS_NUMBER_UNION:
					numbers_p++;
					break;
				}
			}
			while (head->r.cond_index < condc) {
				const u8 match = condp->equals;
				const u8 left = condp->left;
				const u8 right = condp->right;
				if (!ccs_flush(head))
					return false;
				condp++;
				head->r.cond_index++;
				ccs_set_space(head);
				switch (left) {
				case CCS_ARGV_ENTRY:
					ccs_io_printf(head,
						      "exec.argv[%lu]%s=\"",
						      argv->index,
						      argv->is_not ? "!" : "");
					ccs_set_string(head,
						       argv->value->name);
					ccs_set_string(head, "\"");
					argv++;
					continue;
				case CCS_ENVP_ENTRY:
					ccs_set_string(head, "exec.envp[\"");
					ccs_set_string(head, envp->name->name);
					ccs_io_printf(head, "\"]%s=",
						      envp->is_not ? "!" : "");
					if (envp->value) {
						ccs_set_string(head, "\"");
						ccs_set_string(head, envp->
							       value->name);
						ccs_set_string(head, "\"");
					} else {
						ccs_set_string(head, "NULL");
					}
					envp++;
					continue;
				case CCS_NUMBER_UNION:
					ccs_print_number_union_nospace
						(head, numbers_p++);
					break;
				default:
					ccs_set_string(head,
					       ccs_condition_keyword[left]);
					break;
				}
				ccs_set_string(head, match ? "=" : "!=");
				switch (right) {
				case CCS_NAME_UNION:
					ccs_print_name_union_quoted
						(head, names_p++);
					break;
				case CCS_NUMBER_UNION:
					ccs_print_number_union_nospace
						(head, numbers_p++);
					break;
				default:
					ccs_set_string(head,
					       ccs_condition_keyword[right]);
					break;
				}
			}
		}
		head->r.cond_step++;
		/* fall through */
	case 2:
		if (!ccs_flush(head))
			break;
		head->r.cond_step++;
		/* fall through */
	case 3:
		if (cond->grant_log != CCS_GRANTLOG_AUTO)
			ccs_io_printf(head, " grant_log=%s",
				      ccs_yesno(cond->grant_log ==
						CCS_GRANTLOG_YES));
		if (cond->transit && !cond->exec_transit) {
			const char *name = cond->transit->name;
			ccs_set_string(head, " auto_domain_transition=\"");
			ccs_set_string(head, name);
			ccs_set_string(head, "\"");
		}
		ccs_set_lf(head);
		return true;
	}
	return false;
}

/**
 * ccs_set_group - Print "acl_group " header keyword and category name.
 *
 * @head:     Pointer to "struct ccs_io_buffer".
 * @category: Category name.
 *
 * Returns nothing.
 */
static void ccs_set_group(struct ccs_io_buffer *head, const char *category)
{
	if (head->type == CCS_EXCEPTIONPOLICY) {
		ccs_print_namespace(head);
		ccs_io_printf(head, "acl_group %u ", head->r.acl_group_index);
	}
	ccs_set_string(head, category);
}

/**
 * ccs_print_entry - Print an ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @acl:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_entry(struct ccs_io_buffer *head,
			    const struct ccs_acl_info *acl)
{
	const u8 acl_type = acl->type;
	const bool may_trigger_transition = acl->cond && acl->cond->transit;
	bool first = true;
	u8 bit;
	if (head->r.print_cond_part)
		goto print_cond_part;
	if (acl->is_deleted)
		return true;
	if (!ccs_flush(head))
		return false;
	else if (acl_type == CCS_TYPE_PATH_ACL) {
		struct ccs_path_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		const u16 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_PATH_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (head->r.print_transition_related_only &&
			    bit != CCS_TYPE_EXECUTE && !may_trigger_transition)
				continue;
			if (first) {
				ccs_set_group(head, "file ");
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_path_keyword[bit]);
		}
		if (first)
			return true;
		ccs_print_name_union(head, &ptr->name);
	} else if (acl_type == CCS_TYPE_AUTO_EXECUTE_HANDLER ||
		   acl_type == CCS_TYPE_DENIED_EXECUTE_HANDLER) {
		struct ccs_handler_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "task ");
		ccs_set_string(head, acl_type == CCS_TYPE_AUTO_EXECUTE_HANDLER
			       ? "auto_execute_handler " :
			       "denied_execute_handler ");
		ccs_set_string(head, ptr->handler->name);
	} else if (acl_type == CCS_TYPE_AUTO_TASK_ACL ||
		   acl_type == CCS_TYPE_MANUAL_TASK_ACL) {
		struct ccs_task_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "task ");
		ccs_set_string(head, acl_type == CCS_TYPE_AUTO_TASK_ACL ?
			       "auto_domain_transition " :
			       "manual_domain_transition ");
		ccs_set_string(head, ptr->domainname->name);
	} else if (head->r.print_transition_related_only &&
		   !may_trigger_transition) {
		return true;
	} else if (acl_type == CCS_TYPE_MKDEV_ACL) {
		struct ccs_mkdev_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_MKDEV_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group(head, "file ");
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_mac_keywords
				       [ccs_pnnn2mac[bit]]);
		}
		if (first)
			return true;
		ccs_print_name_union(head, &ptr->name);
		ccs_print_number_union(head, &ptr->mode);
		ccs_print_number_union(head, &ptr->major);
		ccs_print_number_union(head, &ptr->minor);
	} else if (acl_type == CCS_TYPE_PATH2_ACL) {
		struct ccs_path2_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_PATH2_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group(head, "file ");
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_mac_keywords
				       [ccs_pp2mac[bit]]);
		}
		if (first)
			return true;
		ccs_print_name_union(head, &ptr->name1);
		ccs_print_name_union(head, &ptr->name2);
	} else if (acl_type == CCS_TYPE_PATH_NUMBER_ACL) {
		struct ccs_path_number_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_PATH_NUMBER_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group(head, "file ");
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_mac_keywords
				       [ccs_pn2mac[bit]]);
		}
		if (first)
			return true;
		ccs_print_name_union(head, &ptr->name);
		ccs_print_number_union(head, &ptr->number);
	} else if (acl_type == CCS_TYPE_ENV_ACL) {
		struct ccs_env_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "misc env ");
		ccs_set_string(head, ptr->env->name);
	} else if (acl_type == CCS_TYPE_CAPABILITY_ACL) {
		struct ccs_capability_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "capability ");
		ccs_set_string(head, ccs_mac_keywords
			       [ccs_c2mac[ptr->operation]]);
	} else if (acl_type == CCS_TYPE_INET_ACL) {
		struct ccs_inet_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_NETWORK_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group(head, "network inet ");
				ccs_set_string(head, ccs_proto_keyword
					       [ptr->protocol]);
				ccs_set_space(head);
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_socket_keyword[bit]);
		}
		if (first)
			return true;
		ccs_set_space(head);
		if (ptr->address.group) {
			ccs_set_string(head, "@");
			ccs_set_string(head,
				       ptr->address.group->group_name->name);
		} else {
			char buf[128];
			ccs_print_ip(buf, sizeof(buf), &ptr->address);
			ccs_io_printf(head, "%s", buf);
		}
		ccs_print_number_union(head, &ptr->port);
	} else if (acl_type == CCS_TYPE_UNIX_ACL) {
		struct ccs_unix_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < CCS_MAX_NETWORK_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group(head, "network unix ");
				ccs_set_string(head, ccs_proto_keyword
					       [ptr->protocol]);
				ccs_set_space(head);
				first = false;
			} else {
				ccs_set_slash(head);
			}
			ccs_set_string(head, ccs_socket_keyword[bit]);
		}
		if (first)
			return true;
		ccs_print_name_union(head, &ptr->name);
	} else if (acl_type == CCS_TYPE_SIGNAL_ACL) {
		struct ccs_signal_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "ipc signal ");
		ccs_print_number_union_nospace(head, &ptr->sig);
		ccs_set_space(head);
		ccs_set_string(head, ptr->domainname->name);
	} else if (acl_type == CCS_TYPE_MOUNT_ACL) {
		struct ccs_mount_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group(head, "file mount");
		ccs_print_name_union(head, &ptr->dev_name);
		ccs_print_name_union(head, &ptr->dir_name);
		ccs_print_name_union(head, &ptr->fs_type);
		ccs_print_number_union(head, &ptr->flags);
	}
	if (acl->cond) {
		head->r.print_cond_part = true;
		head->r.cond_step = 0;
		if (!ccs_flush(head))
			return false;
print_cond_part:
		if (!ccs_print_condition(head, acl->cond))
			return false;
		head->r.print_cond_part = false;
	} else {
		ccs_set_lf(head);
	}
	return true;
}

/**
 * ccs_read_domain2 - Read domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @list: Pointer to "struct list_head".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_domain2(struct ccs_io_buffer *head,
			     struct list_head *list)
{
	list_for_each_cookie(head->r.acl, list) {
		struct ccs_acl_info *ptr =
			list_entry(head->r.acl, typeof(*ptr), list);
		if (!ccs_print_entry(head, ptr))
			return false;
	}
	head->r.acl = NULL;
	return true;
}

/**
 * ccs_read_domain - Read domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_domain(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	list_for_each_cookie(head->r.domain, &ccs_domain_list) {
		struct ccs_domain_info *domain =
			list_entry(head->r.domain, typeof(*domain), list);
		switch (head->r.step) {
			u8 i;
		case 0:
			if (domain->is_deleted &&
			    !head->r.print_this_domain_only)
				continue;
			/* Print domainname and flags. */
			ccs_set_string(head, domain->domainname->name);
			ccs_set_lf(head);
			ccs_io_printf(head, "use_profile %u\n",
				      domain->profile);
			ccs_io_printf(head, "use_group %u\n", domain->group);
			for (i = 0; i < CCS_MAX_DOMAIN_INFO_FLAGS; i++)
				if (domain->flags[i])
					ccs_set_string(head, ccs_dif[i]);
			head->r.step++;
			ccs_set_lf(head);
			/* fall through */
		case 1:
			if (!ccs_read_domain2(head, &domain->acl_info_list))
				return;
			head->r.step++;
			if (!ccs_set_lf(head))
				return;
			/* fall through */
		case 2:
			head->r.step = 0;
			if (head->r.print_this_domain_only)
				goto done;
		}
	}
done:
	head->r.eof = true;
}

/**
 * ccs_write_pid - Specify PID to obtain domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_write_pid(struct ccs_io_buffer *head)
{
	head->r.eof = false;
	return 0;
}

/**
 * ccs_read_pid - Read information of a process.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the domainname which the specified PID is in or
 * process information of the specified PID on success,
 * empty string otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_pid(struct ccs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	bool global_pid = false;
	unsigned int pid;
	struct task_struct *p;
	struct ccs_domain_info *domain = NULL;
	u32 ccs_flags = 0;
	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf) {
		head->r.eof = true;
		return; /* Do nothing if open(O_RDONLY). */
	}
	if (head->r.w_pos || head->r.eof)
		return;
	head->r.eof = true;
	if (ccs_str_starts(&buf, "info "))
		task_info = true;
	if (ccs_str_starts(&buf, "global-pid "))
		global_pid = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	ccs_tasklist_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (global_pid)
		p = ccsecurity_exports.find_task_by_pid_ns(pid, &init_pid_ns);
	else
		p = ccsecurity_exports.find_task_by_vpid(pid);
#else
	p = find_task_by_pid(pid);
#endif
	if (p) {
		domain = ccs_task_domain(p);
		ccs_flags = ccs_task_flags(p);
	}
	ccs_tasklist_unlock();
	if (!domain)
		return;
	if (!task_info) {
		ccs_io_printf(head, "%u %u ", pid, domain->profile);
		ccs_set_string(head, domain->domainname->name);
	} else {
		ccs_io_printf(head, "%u manager=%s execute_handler=%s ", pid,
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_MANAGER),
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_EXECUTE_HANDLER));
	}
}

/* String table for domain transition control keywords. */
static const char * const ccs_transition_type[CCS_MAX_TRANSITION_TYPE] = {
	[CCS_TRANSITION_CONTROL_NO_RESET]      = "no_reset_domain ",
	[CCS_TRANSITION_CONTROL_RESET]         = "reset_domain ",
	[CCS_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[CCS_TRANSITION_CONTROL_INITIALIZE]    = "initialize_domain ",
	[CCS_TRANSITION_CONTROL_NO_KEEP]       = "no_keep_domain ",
	[CCS_TRANSITION_CONTROL_KEEP]          = "keep_domain ",
};

/* String table for grouping keywords. */
static const char * const ccs_group_name[CCS_MAX_GROUP] = {
	[CCS_PATH_GROUP]    = "path_group ",
	[CCS_NUMBER_GROUP]  = "number_group ",
	[CCS_ADDRESS_GROUP] = "address_group ",
};

/**
 * ccs_write_exception - Write exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_exception(struct ccs_io_buffer *head)
{
	const bool is_delete = head->w.is_delete;
	struct ccs_acl_param param = {
		.ns = head->w.ns,
		.is_delete = is_delete,
		.data = head->write_buf,
	};
	u8 i;
	if (ccs_str_starts(&param.data, "aggregator "))
		return ccs_write_aggregator(&param);
	if (ccs_str_starts(&param.data, "deny_autobind "))
		return ccs_write_reserved_port(&param);
	for (i = 0; i < CCS_MAX_TRANSITION_TYPE; i++)
		if (ccs_str_starts(&param.data, ccs_transition_type[i]))
			return ccs_write_transition_control(&param, i);
	for (i = 0; i < CCS_MAX_GROUP; i++)
		if (ccs_str_starts(&param.data, ccs_group_name[i]))
			return ccs_write_group(&param, i);
	if (ccs_str_starts(&param.data, "acl_group ")) {
		unsigned int group;
		char *data;
		group = simple_strtoul(param.data, &data, 10);
		if (group < CCS_MAX_ACL_GROUPS && *data++ == ' ')
			return ccs_write_domain2(head->w.ns,
						 &head->w.ns->acl_group[group],
						 data, is_delete);
	}
	return -EINVAL;
}

/**
 * ccs_read_group - Read "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @idx:  Index number.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_group(struct ccs_io_buffer *head, const int idx)
{
	struct ccs_policy_namespace *ns = container_of(head->r.ns, typeof(*ns),
						       namespace_list);
	struct list_head *list = &ns->group_list[idx];
	list_for_each_cookie(head->r.group, list) {
		struct ccs_group *group =
			list_entry(head->r.group, typeof(*group), head.list);
		list_for_each_cookie(head->r.acl, &group->member_list) {
			struct ccs_acl_head *ptr =
				list_entry(head->r.acl, typeof(*ptr), list);
			if (ptr->is_deleted)
				continue;
			if (!ccs_flush(head))
				return false;
			ccs_print_namespace(head);
			ccs_set_string(head, ccs_group_name[idx]);
			ccs_set_string(head, group->group_name->name);
			if (idx == CCS_PATH_GROUP) {
				ccs_set_space(head);
				ccs_set_string(head, container_of
					       (ptr, struct ccs_path_group,
						head)->member_name->name);
			} else if (idx == CCS_NUMBER_GROUP) {
				ccs_print_number_union(head, &container_of
					       (ptr, struct ccs_number_group,
						head)->number);
			} else if (idx == CCS_ADDRESS_GROUP) {
				char buffer[128];
				struct ccs_address_group *member =
					container_of(ptr, typeof(*member),
						     head);
				ccs_print_ip(buffer, sizeof(buffer),
					     &member->address);
				ccs_io_printf(head, " %s", buffer);
			}
			ccs_set_lf(head);
		}
		head->r.acl = NULL;
	}
	head->r.group = NULL;
	return true;
}

/**
 * ccs_read_policy - Read "struct ccs_..._entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @idx:  Index number.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_policy(struct ccs_io_buffer *head, const int idx)
{
	struct ccs_policy_namespace *ns = container_of(head->r.ns, typeof(*ns),
						       namespace_list);
	struct list_head *list = &ns->policy_list[idx];
	list_for_each_cookie(head->r.acl, list) {
		struct ccs_acl_head *acl =
			container_of(head->r.acl, typeof(*acl), list);
		if (acl->is_deleted)
			continue;
		if (head->r.print_transition_related_only &&
		    idx != CCS_ID_TRANSITION_CONTROL)
			continue;
		if (!ccs_flush(head))
			return false;
		switch (idx) {
		case CCS_ID_TRANSITION_CONTROL:
			{
				struct ccs_transition_control *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_print_namespace(head);
				ccs_set_string(head,
					       ccs_transition_type[ptr->type]);
				ccs_set_string(head, ptr->program ?
					       ptr->program->name : "any");
				ccs_set_string(head, " from ");
				ccs_set_string(head, ptr->domainname ?
					       ptr->domainname->name : "any");
			}
			break;
		case CCS_ID_AGGREGATOR:
			{
				struct ccs_aggregator *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_print_namespace(head);
				ccs_set_string(head, "aggregator ");
				ccs_set_string(head, ptr->original_name->name);
				ccs_set_space(head);
				ccs_set_string(head,
					       ptr->aggregated_name->name);
			}
			break;
		case CCS_ID_RESERVEDPORT:
			{
				struct ccs_reserved *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_print_namespace(head);
				ccs_set_string(head, "deny_autobind ");
				ccs_print_number_union_nospace(head,
							       &ptr->port);
			}
			break;
		default:
			continue;
		}
		ccs_set_lf(head);
	}
	head->r.acl = NULL;
	return true;
}

/**
 * ccs_read_exception - Read exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_exception(struct ccs_io_buffer *head)
{
	struct ccs_policy_namespace *ns = container_of(head->r.ns, typeof(*ns),
						       namespace_list);
	if (head->r.eof)
		return;
	while (head->r.step < CCS_MAX_POLICY &&
	       ccs_read_policy(head, head->r.step))
		head->r.step++;
	if (head->r.step < CCS_MAX_POLICY)
		return;
	while (head->r.step < CCS_MAX_POLICY + CCS_MAX_GROUP &&
	       ccs_read_group(head, head->r.step - CCS_MAX_POLICY))
		head->r.step++;
	if (head->r.step < CCS_MAX_POLICY + CCS_MAX_GROUP)
		return;
	while (head->r.step < CCS_MAX_POLICY + CCS_MAX_GROUP
	       + CCS_MAX_ACL_GROUPS) {
		head->r.acl_group_index =
			head->r.step - CCS_MAX_POLICY - CCS_MAX_GROUP;
		if (!ccs_read_domain2(head, &ns->acl_group
				      [head->r.acl_group_index]))
			return;
		head->r.step++;
	}
	head->r.eof = true;
}

/* Wait queue for kernel -> userspace notification. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_query_wait);
/* Wait queue for userspace -> kernel notification. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_answer_wait);

/* Structure for query. */
struct ccs_query {
	struct list_head list;
	char *query;
	size_t query_len;
	unsigned int serial;
	u8 timer;
	u8 answer;
	u8 retry;
};

/* The list for "struct ccs_query". */
static LIST_HEAD(ccs_query_list);

/* Lock for manipulating ccs_query_list. */
static DEFINE_SPINLOCK(ccs_query_list_lock);

/* Number of "struct file" referring /proc/ccs/query interface. */
static atomic_t ccs_query_observers = ATOMIC_INIT(0);

/**
 * ccs_truncate - Truncate a line.
 *
 * @str: String to truncate.
 *
 * Returns length of truncated @str.
 */
static int ccs_truncate(char *str)
{
	char *start = str;
	while (*(unsigned char *) str > (unsigned char) ' ')
		str++;
	*str = '\0';
	return strlen(start) + 1;
}

/**
 * ccs_add_entry - Add an ACL to current thread's domain. Used by learning mode.
 *
 * @header: Lines containing ACL.
 *
 * Returns nothing.
 */
static void ccs_add_entry(char *header)
{
	char *buffer;
	char *realpath = NULL;
	char *argv0 = NULL;
	char *symlink = NULL;
	char *handler;
	char *cp = strchr(header, '\n');
	int len;
	if (!cp)
		return;
	cp = strchr(cp + 1, '\n');
	if (!cp)
		return;
	*cp++ = '\0';
	len = strlen(cp) + 1;
	/* strstr() will return NULL if ordering is wrong. */
	if (*cp == 'f') {
		argv0 = strstr(header, " argv[]={ \"");
		if (argv0) {
			argv0 += 10;
			len += ccs_truncate(argv0) + 14;
		}
		realpath = strstr(header, " exec={ realpath=\"");
		if (realpath) {
			realpath += 8;
			len += ccs_truncate(realpath) + 6;
		}
		symlink = strstr(header, " symlink.target=\"");
		if (symlink)
			len += ccs_truncate(symlink + 1) + 1;
	}
	handler = strstr(header, "type=execute_handler");
	if (handler)
		len += ccs_truncate(handler) + 6;
	buffer = kmalloc(len, CCS_GFP_FLAGS);
	if (!buffer)
		return;
	snprintf(buffer, len - 1, "%s", cp);
	if (handler)
		ccs_addprintf(buffer, len, " task.%s", handler);
	if (realpath)
		ccs_addprintf(buffer, len, " exec.%s", realpath);
	if (argv0)
		ccs_addprintf(buffer, len, " exec.argv[0]=%s", argv0);
	if (symlink)
		ccs_addprintf(buffer, len, "%s", symlink);
	ccs_normalize_line(buffer);
	{
		struct ccs_domain_info *domain = ccs_current_domain();
		if (!ccs_write_domain2(domain->ns, &domain->acl_info_list,
				       buffer, false))
			ccs_update_stat(CCS_STAT_POLICY_UPDATES);
	}
	kfree(buffer);
}

/**
 * ccs_supervisor - Ask for the supervisor's decision.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns 0 if the supervisor decided to permit the access request which
 * violated the policy in enforcing mode, CCS_RETRY_REQUEST if the supervisor
 * decided to retry the access request which violated the policy in enforcing
 * mode, 0 if it is not in enforcing mode, -EPERM otherwise.
 */
int ccs_supervisor(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int error;
	int len;
	static unsigned int ccs_serial;
	struct ccs_query entry = { };
	bool quota_exceeded = false;
	va_start(args, fmt);
	len = vsnprintf((char *) &len, 1, fmt, args) + 1;
	va_end(args);
	/* Write /proc/ccs/audit. */
	va_start(args, fmt);
	ccs_write_log2(r, len, fmt, args);
	va_end(args);
	/* Nothing more to do if granted. */
	if (r->granted)
		return 0;
	if (r->mode)
		ccs_update_stat(r->mode);
	switch (r->mode) {
		int i;
		struct ccs_profile *p;
	case CCS_CONFIG_ENFORCING:
		error = -EPERM;
		if (atomic_read(&ccs_query_observers))
			break;
		if (r->dont_sleep_on_enforce_error)
			goto out;
		p = ccs_profile(r->profile);
		/* Check enforcing_penalty parameter. */
		for (i = 0; i < p->pref[CCS_PREF_ENFORCING_PENALTY]; i++) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
		goto out;
	case CCS_CONFIG_LEARNING:
		error = 0;
		/* Check max_learning_entry parameter. */
		if (ccs_domain_quota_ok(r))
			break;
		/* fall through */
	default:
		return 0;
	}
	/* Get message. */
	va_start(args, fmt);
	entry.query = ccs_init_log(r, len, fmt, args);
	va_end(args);
	if (!entry.query)
		goto out;
	entry.query_len = strlen(entry.query) + 1;
	if (!error) {
		ccs_add_entry(entry.query);
		goto out;
	}
	len = ccs_round2(entry.query_len);
	spin_lock(&ccs_query_list_lock);
	if (ccs_memory_quota[CCS_MEMORY_QUERY] &&
	    ccs_memory_used[CCS_MEMORY_QUERY] + len
	    >= ccs_memory_quota[CCS_MEMORY_QUERY]) {
		quota_exceeded = true;
	} else {
		entry.serial = ccs_serial++;
		entry.retry = r->retry;
		ccs_memory_used[CCS_MEMORY_QUERY] += len;
		list_add_tail(&entry.list, &ccs_query_list);
	}
	spin_unlock(&ccs_query_list_lock);
	if (quota_exceeded)
		goto out;
	/* Give 10 seconds for supervisor's opinion. */
	while (entry.timer < 10) {
		wake_up_all(&ccs_query_wait);
		if (wait_event_interruptible_timeout
		    (ccs_answer_wait, entry.answer ||
		     !atomic_read(&ccs_query_observers), HZ))
			break;
		else
			entry.timer++;
	}
	spin_lock(&ccs_query_list_lock);
	list_del(&entry.list);
	ccs_memory_used[CCS_MEMORY_QUERY] -= len;
	spin_unlock(&ccs_query_list_lock);
	switch (entry.answer) {
	case 3: /* Asked to retry by administrator. */
		error = CCS_RETRY_REQUEST;
		r->retry++;
		break;
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	default:
		/* Timed out or rejected by administrator. */
		break;
	}
out:
	kfree(entry.query);
	return error;
}

/**
 * ccs_poll_query - poll() for /proc/ccs/query.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read, 0 otherwise.
 *
 * Waits for access requests which violated policy in enforcing mode.
 */
static int ccs_poll_query(struct file *file, poll_table *wait)
{
	struct list_head *tmp;
	bool found = false;
	u8 i;
	for (i = 0; i < 2; i++) {
		spin_lock(&ccs_query_list_lock);
		list_for_each(tmp, &ccs_query_list) {
			struct ccs_query *ptr =
				list_entry(tmp, typeof(*ptr), list);
			if (ptr->answer)
				continue;
			found = true;
			break;
		}
		spin_unlock(&ccs_query_list_lock);
		if (found)
			return POLLIN | POLLRDNORM;
		if (i)
			break;
		poll_wait(file, &ccs_query_wait, wait);
	}
	return 0;
}

/**
 * ccs_read_query - Read access requests which violated policy in enforcing mode.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_query(struct ccs_io_buffer *head)
{
	struct list_head *tmp;
	unsigned int pos = 0;
	size_t len = 0;
	char *buf;
	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (!len) {
		head->r.query_index = 0;
		return;
	}
	buf = kzalloc(len + 32, CCS_GFP_FLAGS);
	if (!buf)
		return;
	pos = 0;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		/*
		 * Some query can be skipped because ccs_query_list
		 * can change, but I don't care.
		 */
		if (len == ptr->query_len)
			snprintf(buf, len + 31, "Q%u-%hu\n%s", ptr->serial,
				 ptr->retry, ptr->query);
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (buf[0]) {
		head->read_buf = buf;
		head->r.w[head->r.w_pos++] = buf;
		head->r.query_index++;
	} else {
		kfree(buf);
	}
}

/**
 * ccs_write_answer - Write the supervisor's decision.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_answer(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial;
	unsigned int answer;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		ptr->timer = 0;
	}
	spin_unlock(&ccs_query_list_lock);
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->serial != serial)
			continue;
		if (!ptr->answer)
			ptr->answer = (u8) answer;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	wake_up_all(&ccs_answer_wait);
	return 0;
}

/**
 * ccs_read_version - Get version.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_version(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	ccs_set_string(head, "1.8.2");
	head->r.eof = true;
}

/* String table for /proc/ccs/stat interface. */
static const char * const ccs_policy_headers[CCS_MAX_POLICY_STAT] = {
	[CCS_STAT_POLICY_UPDATES]    = "update:",
	[CCS_STAT_POLICY_LEARNING]   = "violation in learning mode:",
	[CCS_STAT_POLICY_PERMISSIVE] = "violation in permissive mode:",
	[CCS_STAT_POLICY_ENFORCING]  = "violation in enforcing mode:",
};

/* String table for /proc/ccs/stat interface. */
static const char * const ccs_memory_headers[CCS_MAX_MEMORY_STAT] = {
	[CCS_MEMORY_POLICY]     = "policy:",
	[CCS_MEMORY_AUDIT]      = "audit log:",
	[CCS_MEMORY_QUERY]      = "query message:",
};

/* Timestamp counter for last updated. */
static unsigned int ccs_stat_updated[CCS_MAX_POLICY_STAT];
/* Counter for number of updates. */
static unsigned int ccs_stat_modified[CCS_MAX_POLICY_STAT];

/**
 * ccs_update_stat - Update statistic counters.
 *
 * @index: Index for policy type.
 *
 * Returns nothing.
 */
void ccs_update_stat(const u8 index)
{
	struct timeval tv;
	do_gettimeofday(&tv);
	/*
	 * I don't use atomic operations because race condition is not fatal.
	 */
	ccs_stat_updated[index]++;
	ccs_stat_modified[index] = tv.tv_sec;
}

/**
 * ccs_read_stat - Read statistic data.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_stat(struct ccs_io_buffer *head)
{
	u8 i;
	unsigned int total = 0;
	if (head->r.eof)
		return;
	for (i = 0; i < CCS_MAX_POLICY_STAT; i++) {
		ccs_io_printf(head, "Policy %-30s %10u", ccs_policy_headers[i],
			      ccs_stat_updated[i]);
		if (ccs_stat_modified[i]) {
			struct ccs_time stamp;
			ccs_convert_time(ccs_stat_modified[i], &stamp);
			ccs_io_printf(head, " (Last: %04u/%02u/%02u "
				      "%02u:%02u:%02u)",
				      stamp.year, stamp.month, stamp.day,
				      stamp.hour, stamp.min, stamp.sec);
		}
		ccs_set_lf(head);
	}
	for (i = 0; i < CCS_MAX_MEMORY_STAT; i++) {
		unsigned int used = ccs_memory_used[i];
		total += used;
		ccs_io_printf(head, "Memory used by %-22s %10u",
			      ccs_memory_headers[i], used);
		used = ccs_memory_quota[i];
		if (used)
			ccs_io_printf(head, " (Quota: %10u)", used);
		ccs_set_lf(head);
	}
	ccs_io_printf(head, "Total memory used:                    %10u\n",
		      total);
	head->r.eof = true;
}

/**
 * ccs_write_stat - Set memory quota.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_write_stat(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	u8 i;
	if (ccs_str_starts(&data, "Memory used by "))
		for (i = 0; i < CCS_MAX_MEMORY_STAT; i++)
			if (ccs_str_starts(&data, ccs_memory_headers[i])) {
				if (*data == ' ')
					data++;
				ccs_memory_quota[i] =
					simple_strtoul(data, NULL, 10);
			}
	return 0;
}

/**
 * ccs_open_control - open() for /proc/ccs/ interface.
 *
 * @type: Type of interface.
 * @file: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_open_control(const u8 type, struct file *file)
{
	struct ccs_io_buffer *head = kzalloc(sizeof(*head), CCS_GFP_FLAGS);
	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	head->type = type;
	if (type == CCS_EXECUTE_HANDLER) {
		/* Allow execute_handler to read process's status. */
		if (!(ccs_current_flags() & CCS_TASK_IS_EXECUTE_HANDLER)) {
			kfree(head);
			return -EPERM;
		}
	}
	if ((file->f_mode & FMODE_READ) && type != CCS_AUDIT &&
	    type != CCS_QUERY) {
		/* Don't allocate read_buf for poll() access. */
		head->readbuf_size = 4096;
		head->read_buf = kzalloc(head->readbuf_size, CCS_GFP_FLAGS);
		if (!head->read_buf) {
			kfree(head);
			return -ENOMEM;
		}
	}
	if (file->f_mode & FMODE_WRITE) {
		head->writebuf_size = 4096;
		head->write_buf = kzalloc(head->writebuf_size, CCS_GFP_FLAGS);
		if (!head->write_buf) {
			kfree(head->read_buf);
			kfree(head);
			return -ENOMEM;
		}
	}
	/*
	 * If the file is /proc/ccs/query, increment the observer counter.
	 * The obserber counter is used by ccs_supervisor() to see if
	 * there is some process monitoring /proc/ccs/query.
	 */
	if (type == CCS_QUERY)
		atomic_inc(&ccs_query_observers);
	file->private_data = head;
	ccs_notify_gc(head, true);
	return 0;
}

/**
 * ccs_poll_control - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns return value of poll().
 *
 * Waits for read readiness.
 * /proc/ccs/query is handled by /usr/sbin/ccs-queryd and
 * /proc/ccs/audit is handled by /usr/sbin/ccs-auditd.
 */
int ccs_poll_control(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	switch (head->type) {
	case CCS_AUDIT:
		return ccs_poll_log(file, wait);
	case CCS_QUERY:
		return ccs_poll_query(file, wait);
	default:
		return -ENOSYS;
	}
}

/**
 * ccs_set_namespace_cursor - Set namespace to read.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static inline void ccs_set_namespace_cursor(struct ccs_io_buffer *head)
{
	struct list_head *ns;
	if (head->type != CCS_EXCEPTIONPOLICY && head->type != CCS_PROFILE)
		return;
	/*
	 * If this is the first read, or reading previous namespace finished
	 * and has more namespaces to read, update the namespace cursor.
	 */
	ns = head->r.ns;
	if (!ns || (head->r.eof && ns->next != &ccs_namespace_list)) {
		/* Clearing is OK because ccs_flush() returned true. */
		memset(&head->r, 0, sizeof(head->r));
		head->r.ns = ns ? ns->next : ccs_namespace_list.next;
	}
}

/**
 * ccs_has_more_namespace - Check for unread namespaces.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true if we have more entries to print, false otherwise.
 */
static inline bool ccs_has_more_namespace(struct ccs_io_buffer *head)
{
	return (head->type == CCS_EXCEPTIONPOLICY ||
		head->type == CCS_PROFILE) && head->r.eof &&
		head->r.ns->next != &ccs_namespace_list;
}

/**
 * ccs_read_control - read() for /proc/ccs/ interface.
 *
 * @head:       Pointer to "struct ccs_io_buffer".
 * @buffer:     Poiner to buffer to write to.
 * @buffer_len: Size of @buffer.
 *
 * Returns bytes read on success, negative value otherwise.
 */
ssize_t ccs_read_control(struct ccs_io_buffer *head, char __user *buffer,
			 const size_t buffer_len)
{
	int len;
	int idx;
	if (!access_ok(VERIFY_WRITE, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	head->read_user_buf = buffer;
	head->read_user_buf_avail = buffer_len;
	idx = ccs_read_lock();
	if (ccs_flush(head))
		/* Call the policy handler. */
		do {
			ccs_set_namespace_cursor(head);
			switch (head->type) {
			case CCS_DOMAINPOLICY:
				ccs_read_domain(head);
				break;
			case CCS_EXCEPTIONPOLICY:
				ccs_read_exception(head);
				break;
			case CCS_AUDIT:
				ccs_read_log(head);
				break;
			case CCS_EXECUTE_HANDLER:
			case CCS_PROCESS_STATUS:
				ccs_read_pid(head);
				break;
			case CCS_VERSION:
				ccs_read_version(head);
				break;
			case CCS_STAT:
				ccs_read_stat(head);
				break;
			case CCS_PROFILE:
				ccs_read_profile(head);
				break;
			case CCS_QUERY:
				ccs_read_query(head);
				break;
			case CCS_MANAGER:
				ccs_read_manager(head);
				break;
			}
		} while (ccs_flush(head) && ccs_has_more_namespace(head));
	ccs_read_unlock(idx);
	len = head->read_user_buf - buffer;
	mutex_unlock(&head->io_sem);
	return len;
}

/**
 * ccs_parse_policy - Parse a policy line.
 *
 * @head: Poiter to "struct ccs_io_buffer".
 * @line: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_parse_policy(struct ccs_io_buffer *head, char *line)
{
	/* Delete request? */
	head->w.is_delete = !strncmp(line, "delete ", 7);
	if (head->w.is_delete)
		memmove(line, line + 7, strlen(line + 7) + 1);
	/* Selecting namespace to update. */
	if (head->type == CCS_EXCEPTIONPOLICY || head->type == CCS_PROFILE) {
		if (*line == '<') {
			char *cp = strchr(line, ' ');
			if (cp) {
				*cp++ = '\0';
				head->w.ns = ccs_assign_namespace(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				head->w.ns = NULL;
		} else
			head->w.ns = &ccs_kernel_namespace;
		/* Don't allow updating if namespace is invalid. */
		if (!head->w.ns)
			return -ENOENT;
	}
	/* Do the update. */
	switch (head->type) {
	case CCS_DOMAINPOLICY:
		return ccs_write_domain(head);
	case CCS_EXCEPTIONPOLICY:
		return ccs_write_exception(head);
	case CCS_EXECUTE_HANDLER:
	case CCS_PROCESS_STATUS:
		return ccs_write_pid(head);
	case CCS_STAT:
		return ccs_write_stat(head);
	case CCS_PROFILE:
		return ccs_write_profile(head);
	case CCS_QUERY:
		return ccs_write_answer(head);
	case CCS_MANAGER:
		return ccs_write_manager(head);
	default:
		return -ENOSYS;
	}
}

/**
 * ccs_write_control - write() for /proc/ccs/ interface.
 *
 * @head:       Pointer to "struct ccs_io_buffer".
 * @buffer:     Pointer to buffer to read from.
 * @buffer_len: Size of @buffer.
 *
 * Returns @buffer_len on success, negative value otherwise.
 */
ssize_t ccs_write_control(struct ccs_io_buffer *head,
			  const char __user *buffer, const size_t buffer_len)
{
	int error = buffer_len;
	size_t avail_len = buffer_len;
	char *cp0 = head->write_buf;
	int idx;
	if (!access_ok(VERIFY_READ, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	idx = ccs_read_lock();
	/* Read a line and dispatch it to the policy handler. */
	while (avail_len > 0) {
		char c;
		if (head->w.avail >= head->writebuf_size - 1) {
			const int len = head->writebuf_size * 2;
			char *cp = kzalloc(len, CCS_GFP_FLAGS);
			if (!cp) {
				error = -ENOMEM;
				break;
			}
			memmove(cp, cp0, head->w.avail);
			kfree(cp0);
			head->write_buf = cp;
			cp0 = cp;
			head->writebuf_size = len;
		}
		if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++;
		avail_len--;
		cp0[head->w.avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->w.avail - 1] = '\0';
		head->w.avail = 0;
		ccs_normalize_line(cp0);
		if (!strcmp(cp0, "reset")) {
			head->w.ns = &ccs_kernel_namespace;
			head->w.domain = NULL;
			memset(&head->r, 0, sizeof(head->r));
			continue;
		}
		/* Don't allow updating policies by non manager programs. */
		switch (head->type) {
		case CCS_PROCESS_STATUS:
			/* This does not write anything. */
			break;
		case CCS_DOMAINPOLICY:
			if (ccs_select_domain(head, cp0))
				continue;
			/* fall through */
		case CCS_EXCEPTIONPOLICY:
			if (!strcmp(cp0, "select transition_only")) {
				head->r.print_transition_related_only = true;
				continue;
			}
			/* fall through */
		default:
			if (!ccs_manager()) {
				error = -EPERM;
				goto out;
			}
		}
		switch (ccs_parse_policy(head, cp0)) {
		case -EPERM:
			error = -EPERM;
			goto out;
		case 0:
			/* Update statistics. */
			switch (head->type) {
			case CCS_DOMAINPOLICY:
			case CCS_EXCEPTIONPOLICY:
			case CCS_STAT:
			case CCS_PROFILE:
			case CCS_MANAGER:
				ccs_update_stat(CCS_STAT_POLICY_UPDATES);
				break;
			default:
				break;
			}
			break;
		}
	}
out:
	ccs_read_unlock(idx);
	mutex_unlock(&head->io_sem);
	return error;
}

/**
 * ccs_close_control - close() for /proc/ccs/ interface.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_close_control(struct ccs_io_buffer *head)
{
	/*
	 * If the file is /proc/ccs/query, decrement the observer counter.
	 */
	if (head->type == CCS_QUERY &&
	    atomic_dec_and_test(&ccs_query_observers))
		wake_up_all(&ccs_answer_wait);
	ccs_notify_gc(head, false);
	return 0;
}

/**
 * ccs_policy_io_init - Register hooks for policy I/O.
 *
 * Returns nothing.
 */
void __init ccs_policy_io_init(void)
{
	ccsecurity_ops.check_profile = ccs_check_profile;
}

/**
 * ccs_load_builtin_policy - Load built-in policy.
 *
 * Returns nothing.
 */
void __init ccs_load_builtin_policy(void)
{
	/*
	 * This include file is manually created and contains built-in policy
	 * named "ccs_builtin_profile", "ccs_builtin_exception_policy",
	 * "ccs_builtin_domain_policy", "ccs_builtin_manager",
	 * "ccs_builtin_stat" in the form of "static char [] __initdata".
	 */
#include "builtin-policy.h"
	u8 i;
	const int idx = ccs_read_lock();
	for (i = 0; i < 5; i++) {
		struct ccs_io_buffer head = { };
		char *start = "";
		switch (i) {
		case 0:
			start = ccs_builtin_profile;
			head.type = CCS_PROFILE;
			break;
		case 1:
			start = ccs_builtin_exception_policy;
			head.type = CCS_EXCEPTIONPOLICY;
			break;
		case 2:
			start = ccs_builtin_domain_policy;
			head.type = CCS_DOMAINPOLICY;
			break;
		case 3:
			start = ccs_builtin_manager;
			head.type = CCS_MANAGER;
			break;
		case 4:
			start = ccs_builtin_stat;
			head.type = CCS_STAT;
			break;
		}
		while (1) {
			char *end = strchr(start, '\n');
			if (!end)
				break;
			*end = '\0';
			ccs_normalize_line(start);
			head.write_buf = start;
			ccs_parse_policy(&head, start);
			start = end + 1;
		}
	}
	ccs_read_unlock(idx);
#ifdef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
	ccs_check_profile();
#endif
}
