/*
 * security/ccsecurity/proc_if.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/version.h>
#include "internal.h"

static bool ccs_check_task_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_task_acl *acl = container_of(ptr, typeof(*acl), head);
	return !ccs_pathcmp(r->param.task.domainname, acl->domainname);
}

/**
 * ccs_write_self - write() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write_self(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *data;		
	int error;
	if (!count || count >= CCS_EXEC_TMPSIZE - 10)
		return -ENOMEM;
	data = kzalloc(count + 1, CCS_GFP_FLAGS);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
	ccs_normalize_line(data);
	if (ccs_correct_domain(data)) {
		const int idx = ccs_read_lock();
		struct ccs_path_info name;
		struct ccs_request_info r;
		name.name = data;
		ccs_fill_path_info(&name);
		/* Check "task manual_transit" permission. */
		ccs_init_request_info(&r, CCS_MAC_FILE_EXECUTE);
		r.param_type = CCS_TYPE_MANUAL_TASK_ACL;
		r.param.task.domainname = &name;
		ccs_check_acl(&r, ccs_check_task_acl);
		if (!r.granted)
			error = -EPERM;
		else
			error = ccs_assign_domain(data, r.profile,
						  ccs_current_domain()->group,
						  true) ? 0 : -ENOENT;
		ccs_read_unlock(idx);
	} else
		error = -EINVAL;
 out:
	kfree(data);
	return error ? error : count;
}

/**
 * ccs_read_self - read() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname which current thread belongs to.
 * @count: Size of @buf.
 * @ppos:  Bytes read by now.
 *
 * Returns read size on success, negative value otherwise.
 */
static int ccs_read_self(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	const char *domain = ccs_current_domain()->domainname->name;
	loff_t len = strlen(domain);
	loff_t pos = *ppos;
	if (pos >= len || !count)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, domain + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/* Operations for /proc/ccs/self_domain interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_self_operations = {
	.write = ccs_write_self,
	.read  = ccs_read_self,
};

static u32 ccs_stat_updated[CCS_MAX_POLICY_STAT];
static u32 ccs_stat_modified[CCS_MAX_POLICY_STAT];

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
 * ccs_read_stat - read() for /proc/ccs/stat interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Buffer.
 * @count: Size of @buf.
 * @ppos:  Bytes read by now.
 *
 * Returns read size on success, negative value otherwise.
 */
static int ccs_read_stat(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	static const char * const headers[CCS_MAX_POLICY_STAT] = {
		[CCS_STAT_POLICY_UPDATES]    = "update:",
		[CCS_STAT_POLICY_LEARNING]   = "violation (learning mode):",
		[CCS_STAT_POLICY_PERMISSIVE] = "violation (permissive mode):",
		[CCS_STAT_POLICY_ENFORCING]  = "violation (enforcing mode):",
	};
	static const char * const headers2[CCS_MAX_MEMORY_STAT] = {
		[CCS_MEMORY_POLICY] = "policy:",
		[CCS_MEMORY_AUDIT]  = "audit log:",
		[CCS_MEMORY_QUERY]  = "query message:",
	};
	char buffer[800];
	loff_t len = 0;
	loff_t pos = *ppos;
	u8 i;
	unsigned int total = 0;
	buf[sizeof(buf) - 1] = '\0';
	for (i = 0; i < CCS_MAX_POLICY_STAT; i++)
		len += snprintf(buffer + len, sizeof(buffer) - len - 1,
				"Last policy %-29s %10u\n"
				"Total policy %-28s %10u\n",
				headers[i], ccs_stat_modified[i],
				headers[i], ccs_stat_updated[i]);
	for (i = 0; i < CCS_MAX_MEMORY_STAT; i++) {
		unsigned int used = ccs_memory_used[i];
		total += used;
		len += snprintf(buffer + len, sizeof(buffer) - len - 1,
				"Memory used by %-26s %10u\n"
				"Memory quota for %-24s %10u\n",
				headers2[i], used,
				headers2[i], ccs_memory_quota[i]);
	}
	snprintf(buffer + len, sizeof(buffer) - len - 1,
		 "Total memory used:                        %10u\n", total);
	len = strlen(buffer);
	if (pos >= len || !count)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, buffer + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/* Operations for /proc/ccs/stat interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_stat_operations = {
	.read  = ccs_read_stat,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 23)
#if !defined(RHEL_VERSION) || RHEL_VERSION != 3 || !defined(RHEL_UPDATE) || RHEL_UPDATE != 9
/**
 * PDE - Get "struct proc_dir_entry".
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns pointer to "struct proc_dir_entry"
 *
 * This is for compatibility with older kernels.
 */
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *) inode->u.generic_ip;
}
#endif
#endif

/**
 * ccs_open - open() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct inode *inode, struct file *file)
{
	return ccs_open_control(((u8 *) PDE(inode)->data) - ((u8 *) NULL),
				file);
}

/**
 * ccs_release - close() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_release(struct inode *inode, struct file *file)
{
	return ccs_close_control(file);
}

/**
 * ccs_poll - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns 0 on success, negative value otherwise.
 */
static unsigned int ccs_poll(struct file *file, poll_table *wait)
{
	return ccs_poll_control(file, wait);
}

/**
 * ccs_read - read() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t ccs_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	return ccs_read_control(file, buf, count);
}

/**
 * ccs_write - write() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	return ccs_write_control(file, buf, count);
}

/* Operations for /proc/ccs/ interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_operations = {
	.open    = ccs_open,
	.release = ccs_release,
	.poll    = ccs_poll,
	.read    = ccs_read,
	.write   = ccs_write,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

struct iattr;

/**
 * proc_notify_change - Update inode's attributes and reflect to the dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * The 2.4 kernels don't allow chmod()/chown() for files in /proc ,
 * while the 2.6 kernels allow.
 * To permit management of /proc/ccs/ interface by non-root user,
 * I modified to allow chmod()/chown() of /proc/ccs/ interface like 2.6 kernels
 * by adding "struct inode_operations"->setattr hook.
 */
static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		goto out;

	error = inode_setattr(inode, iattr);
	if (error)
		goto out;

	de->uid = inode->i_uid;
	de->gid = inode->i_gid;
	de->mode = inode->i_mode;
 out:
	return error;
}

/* The inode operations for /proc/ccs/ directory. */
static struct inode_operations ccs_dir_inode_operations;

/* The inode operations for files under /proc/ccs/ directory. */
static struct inode_operations ccs_file_inode_operations;
#endif

/**
 * ccs_create_entry - Create interface files under /proc/ccs/ directory.
 *
 * @name:   The name of the interface file.
 * @mode:   The permission of the interface file.
 * @parent: The parent directory.
 * @key:    Type of interface.
 *
 * Returns nothing.
 */
static void __init ccs_create_entry(const char *name, const mode_t mode,
				    struct proc_dir_entry *parent,
				    const u8 key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
		if (entry->proc_iops)
			ccs_file_inode_operations = *entry->proc_iops;
		if (!ccs_file_inode_operations.setattr)
			ccs_file_inode_operations.setattr = proc_notify_change;
		entry->proc_iops = &ccs_file_inode_operations;
#endif
	}
}

/**
 * ccs_proc_init - Initialize /proc/ccs/ interface.
 *
 * Returns 0.
 */
static void __init ccs_proc_init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	if (ccs_dir->proc_iops)
		ccs_dir_inode_operations = *ccs_dir->proc_iops;
	if (!ccs_dir_inode_operations.setattr)
		ccs_dir_inode_operations.setattr = proc_notify_change;
	ccs_dir->proc_iops = &ccs_dir_inode_operations;
#endif
	ccs_create_entry("query",            0600, ccs_dir, CCS_QUERY);
	ccs_create_entry("domain_policy",    0600, ccs_dir, CCS_DOMAINPOLICY);
	ccs_create_entry("exception_policy", 0600, ccs_dir,
			 CCS_EXCEPTIONPOLICY);
	ccs_create_entry("grant_log",        0400, ccs_dir, CCS_GRANTLOG);
	ccs_create_entry("reject_log",       0400, ccs_dir, CCS_REJECTLOG);
	ccs_create_entry(".domain_status",   0600, ccs_dir, CCS_DOMAIN_STATUS);
	ccs_create_entry(".process_status",  0600, ccs_dir,
			 CCS_PROCESS_STATUS);
	ccs_create_entry("meminfo",          0600, ccs_dir, CCS_MEMINFO);
	ccs_create_entry("profile",          0600, ccs_dir, CCS_PROFILE);
	ccs_create_entry("manager",          0600, ccs_dir, CCS_MANAGER);
	ccs_create_entry("version",          0400, ccs_dir, CCS_VERSION);
	ccs_create_entry(".execute_handler", 0666, ccs_dir,
			 CCS_EXECUTE_HANDLER);
	{
		struct proc_dir_entry *e = create_proc_entry("self_domain",
							     0666, ccs_dir);
		if (e)
			e->proc_fops = &ccs_self_operations;
		e = create_proc_entry("stat", 0444, ccs_dir);
		if (e)
			e->proc_fops = &ccs_stat_operations;
	}
}

static int __init ccs_init_module(void)
{
	int i;
	for (i = 0; i < CCS_MAX_POLICY; i++)
		INIT_LIST_HEAD(&ccs_policy_list[i]);
	for (i = 0; i < CCS_MAX_GROUP; i++)
		INIT_LIST_HEAD(&ccs_group_list[i]);
	for (i = 0; i < CCS_MAX_LIST; i++)
		INIT_LIST_HEAD(&ccs_shared_list[i]);
	if (ccsecurity_ops.disabled)
		return -EINVAL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 0)
	MOD_INC_USE_COUNT;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
#endif
	ccs_proc_init();
	ccs_mm_init();
	ccs_capability_init();
	ccs_file_init();
	ccs_network_init();
	ccs_signal_init();
	ccs_mount_init();
	ccs_policy_io_init();
	ccs_domain_init();
	return 0;
}

void __init ccs_main_init(void)
{
	ccs_init_module();
}