/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.36   2017/02/20
 */

#include "internal.h"
#include "probe.h"

/* Prototype definition. */
static void ccs_task_security_gc(void);
static int ccs_copy_cred_security(const struct cred *new,
				  const struct cred *old, gfp_t gfp);
static struct ccs_security *ccs_find_cred_security(const struct cred *cred);
static DEFINE_SPINLOCK(ccs_task_security_list_lock);
static atomic_t ccs_in_execve_tasks = ATOMIC_INIT(0);
/*
 * List of "struct ccs_security" for "struct pid".
 *
 * All instances on this list is guaranteed that "struct ccs_security"->pid !=
 * NULL. Also, instances on this list that are in execve() are guaranteed that
 * "struct ccs_security"->cred remembers "struct linux_binprm"->cred with a
 * refcount on "struct linux_binprm"->cred.
 */
struct list_head ccs_task_security_list[CCS_MAX_TASK_SECURITY_HASH];
/*
 * List of "struct ccs_security" for "struct cred".
 *
 * Since the number of "struct cred" is nearly equals to the number of
 * "struct pid", we allocate hash tables like ccs_task_security_list.
 *
 * All instances on this list are guaranteed that "struct ccs_security"->pid ==
 * NULL and "struct ccs_security"->cred != NULL.
 */
static struct list_head ccs_cred_security_list[CCS_MAX_TASK_SECURITY_HASH];

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_oom_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_default_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* For exporting variables and functions. */
struct ccsecurity_exports ccsecurity_exports;
/* Members are updated by loadable kernel module. */
struct ccsecurity_operations ccsecurity_ops;

/* Original hooks. */
static union security_list_options original_cred_prepare;
static union security_list_options original_cred_free;
static union security_list_options original_cred_alloc_blank;

#ifdef CONFIG_AKARI_TRACE_EXECVE_COUNT

/**
 * ccs_update_ee_counter - Update "struct ccs_execve" counter.
 *
 * @count: Count to increment or decrement.
 *
 * Returns updated counter.
 */
static unsigned int ccs_update_ee_counter(int count)
{
	/* Debug counter for detecting "struct ccs_execve" memory leak. */
	static atomic_t ccs_ee_counter = ATOMIC_INIT(0);
	return atomic_add_return(count, &ccs_ee_counter);
}

/**
 * ccs_audit_alloc_execve - Audit allocation of "struct ccs_execve".
 *
 * @ee: Pointer to "struct ccs_execve".
 *
 * Returns nothing.
 */
void ccs_audit_alloc_execve(const struct ccs_execve * const ee)
{
	printk(KERN_INFO "AKARI: Allocated %p by pid=%u (count=%u)\n", ee,
	       current->pid, ccs_update_ee_counter(1) - 1);
}

/**
 * ccs_audit_free_execve - Audit release of "struct ccs_execve".
 *
 * @ee:   Pointer to "struct ccs_execve".
 * @task: True if released by current task, false otherwise.
 *
 * Returns nothing.
 */
void ccs_audit_free_execve(const struct ccs_execve * const ee,
			   const bool is_current)
{
	const unsigned int tmp = ccs_update_ee_counter(-1);
	if (is_current)
		printk(KERN_INFO "AKARI: Releasing %p by pid=%u (count=%u)\n",
		       ee, current->pid, tmp);
	else
		printk(KERN_INFO "AKARI: Releasing %p by kernel (count=%u)\n",
		       ee, tmp);
}

#endif

#if !defined(CONFIG_AKARI_DEBUG)
#define ccs_debug_trace(pos) do { } while (0)
#else
#define ccs_debug_trace(pos)						\
	do {								\
		static bool done;					\
		if (!done) {						\
			printk(KERN_INFO				\
			       "AKARI: Debug trace: " pos " of 4\n");	\
			done = true;					\
		}							\
	} while (0)
#endif

/**
 * ccs_clear_execve - Release memory used by do_execve().
 *
 * @ret:      0 if do_execve() succeeded, negative value otherwise.
 * @security: Pointer to "struct ccs_security".
 *
 * Returns nothing.
 */
static void ccs_clear_execve(int ret, struct ccs_security *security)
{
	struct ccs_execve *ee;
	if (security == &ccs_default_security || security == &ccs_oom_security)
		return;
	ee = security->ee;
	security->ee = NULL;
	if (!ee)
		return;
	atomic_dec(&ccs_in_execve_tasks);
	ccs_finish_execve(ret, ee);
}

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(struct rcu_head *rcu)
{
	struct ccs_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	struct ccs_execve *ee = ptr->ee;
	/*
	 * If this security context was associated with "struct pid" and
	 * ptr->ccs_flags has CCS_TASK_IS_IN_EXECVE set, it indicates that a
	 * "struct task_struct" associated with this security context exited
	 * immediately after do_execve() has failed.
	 */
	if (ptr->pid && (ptr->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
		ccs_debug_trace("1");
		atomic_dec(&ccs_in_execve_tasks);
	}
	/*
	 * If this security context was associated with "struct pid",
	 * drop refcount obtained by get_pid() in ccs_find_task_security().
	 */
	if (ptr->pid) {
		ccs_debug_trace("2");
		put_pid(ptr->pid);
	}
	if (ee) {
		ccs_debug_trace("3");
		ccs_audit_free_execve(ee, false);
		kfree(ee->handler_path);
		kfree(ee);
	}
	kfree(ptr);
}

/**
 * ccs_del_security - Release "struct ccs_security".
 *
 * @ptr: Pointer to "struct ccs_security".
 *
 * Returns nothing.
 */
static void ccs_del_security(struct ccs_security *ptr)
{
	unsigned long flags;
	if (ptr == &ccs_default_security || ptr == &ccs_oom_security)
		return;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
	call_rcu(&ptr->rcu, ccs_rcu_free);
}

/**
 * ccs_add_cred_security - Add "struct ccs_security" to list.
 *
 * @ptr: Pointer to "struct ccs_security".
 *
 * Returns nothing.
 */
static void ccs_add_cred_security(struct ccs_security *ptr)
{
	unsigned long flags;
	struct list_head *list = &ccs_cred_security_list
		[hash_ptr((void *) ptr->cred, CCS_TASK_SECURITY_HASH_BITS)];
#ifdef CONFIG_AKARI_DEBUG
	if (ptr->pid)
		printk(KERN_INFO "AKARI: \"struct ccs_security\"->pid != NULL"
		       "\n");
#endif
	ptr->pid = NULL;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
}

/**
 * ccs_task_create - Make snapshot of security context for new task.
 *
 * @clone_flags: Flags passed to clone().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_task_create(unsigned long clone_flags)
{
	struct ccs_security *old_security;
	struct ccs_security *new_security;
	struct cred *cred = prepare_creds();
	if (!cred)
		return -ENOMEM;
	old_security = ccs_find_task_security(current);
	new_security = ccs_find_cred_security(cred);
	new_security->ccs_domain_info = old_security->ccs_domain_info;
	new_security->ccs_flags = old_security->ccs_flags;
	return commit_creds(cred);
}

/**
 * ccs_cred_prepare - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	int rc1;
	/*
	 * For checking whether reverting domain transition is needed or not.
	 *
	 * See ccs_find_task_security() for reason.
	 */
	if (gfp == GFP_KERNEL)
		ccs_find_task_security(current);
	rc1 = ccs_copy_cred_security(new, old, gfp);
	if (gfp == GFP_KERNEL)
		ccs_task_security_gc();
	if (original_cred_prepare.cred_prepare) {
		const int rc2 = original_cred_prepare.cred_prepare(new, old,
								   gfp);
		if (rc2) {
			ccs_del_security(ccs_find_cred_security(new));
			return rc2;
		}
	}
	return rc1;
}

/**
 * ccs_cred_free - Release memory used by credentials.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void ccs_cred_free(struct cred *cred)
{
	if (original_cred_free.cred_free)
		original_cred_free.cred_free(cred);
	ccs_del_security(ccs_find_cred_security(cred));
}

/**
 * ccs_alloc_cred_security - Allocate memory for new credentials.
 *
 * @cred: Pointer to "struct cred".
 * @gfp:  Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_alloc_cred_security(const struct cred *cred, gfp_t gfp)
{
	struct ccs_security *new_security = kzalloc(sizeof(*new_security),
						    gfp);
	if (!new_security)
		return -ENOMEM;
	new_security->cred = cred;
	ccs_add_cred_security(new_security);
	return 0;
}

/**
 * ccs_cred_alloc_blank - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
	const int rc1 = ccs_alloc_cred_security(new, gfp);
	if (original_cred_alloc_blank.cred_alloc_blank) {
		const int rc2 = original_cred_alloc_blank.
			cred_alloc_blank(new, gfp);
		if (rc2) {
			ccs_del_security(ccs_find_cred_security(new));
			return rc2;
		}
	}
	return rc1;
}

/**
 * ccs_cred_transfer - Transfer "struct ccs_security" between credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void ccs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct ccs_security *new_security = ccs_find_cred_security(new);
	struct ccs_security *old_security = ccs_find_cred_security(old);
	if (new_security == &ccs_default_security ||
	    new_security == &ccs_oom_security ||
	    old_security == &ccs_default_security ||
	    old_security == &ccs_oom_security)
		return;
	new_security->ccs_flags = old_security->ccs_flags;
	new_security->ccs_domain_info = old_security->ccs_domain_info;
}

/**
 * ccs_bprm_committing_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void ccs_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct ccs_security *old_security = ccs_current_security();
	struct ccs_security *new_security;
	if (old_security == &ccs_default_security ||
	    old_security == &ccs_oom_security)
		return;
	ccs_clear_execve(0, old_security);
	/* Update current task's cred's domain for future fork(). */
	new_security = ccs_find_cred_security(bprm->cred);
	new_security->ccs_flags = old_security->ccs_flags;
	new_security->ccs_domain_info = old_security->ccs_domain_info;
}

/**
 * ccs_bprm_check_security - Check permission for execve().
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_bprm_check_security(struct linux_binprm *bprm)
{
	struct ccs_security *security = ccs_current_security();
	int rc;
	if (security == &ccs_default_security || security == &ccs_oom_security)
		return -ENOMEM;
	if (security->ee)
		return 0;
#ifndef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
	if (!ccs_policy_loaded)
		ccs_load_policy(bprm->filename);
#endif
	rc = ccs_start_execve(bprm, &security->ee);
	if (security->ee)
		atomic_inc(&ccs_in_execve_tasks);
	return rc;
}

/**
 * ccs_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_file_open(struct file *f, const struct cred *cred)
{
	return ccs_open_permission(f);
}

#ifdef CONFIG_SECURITY_PATH

/**
 * ccs_path_chown - Check permission for chown()/chgrp().
 *
 * @path:  Pointer to "struct path".
 * @user:  User ID.
 * @group: Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chown(const struct path *path, kuid_t user, kgid_t group)
{
	return ccs_chown_permission(path->dentry, path->mnt, user, group);
}

/**
 * ccs_path_chmod - Check permission for chmod().
 *
 * @path: Pointer to "struct path".
 * @mode: Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chmod(const struct path *path, umode_t mode)
{
	return ccs_chmod_permission(path->dentry, path->mnt, mode);
}

/**
 * ccs_path_chroot - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chroot(const struct path *path)
{
	return ccs_chroot_permission(path);
}

/**
 * ccs_path_truncate - Check permission for truncate().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_truncate(const struct path *path)
{
	return ccs_truncate_permission(path->dentry, path->mnt);
}

#else

/**
 * ccs_inode_setattr - Check permission for chown()/chgrp()/chmod()/truncate().
 *
 * @dentry: Pointer to "struct dentry".
 * @attr:   Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	const int rc1 = (attr->ia_valid & ATTR_UID) ?
		ccs_chown_permission(dentry, NULL, attr->ia_uid, INVALID_GID) :
		0;
	const int rc2 = (attr->ia_valid & ATTR_GID) ?
		ccs_chown_permission(dentry, NULL, INVALID_UID, attr->ia_gid) :
		0;
	const int rc3 = (attr->ia_valid & ATTR_MODE) ?
		ccs_chmod_permission(dentry, NULL, attr->ia_mode) : 0;
	const int rc4 = (attr->ia_valid & ATTR_SIZE) ?
		ccs_truncate_permission(dentry, NULL) : 0;
	if (rc4)
		return rc4;
	if (rc3)
		return rc3;
	if (rc2)
		return rc2;
	return rc1;
}

#endif

/**
 * ccs_inode_getattr - Check permission for stat().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_getattr(const struct path *path)
{
	return ccs_getattr_permission(path->mnt, path->dentry);
}

#ifdef CONFIG_SECURITY_PATH

/**
 * ccs_path_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_mknod(const struct path *dir, struct dentry *dentry,
			  umode_t mode, unsigned int dev)
{
	return ccs_mknod_permission(dentry, dir->mnt, mode, dev);
}

/**
 * ccs_path_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_mkdir(const struct path *dir, struct dentry *dentry,
			  umode_t mode)
{
	return ccs_mkdir_permission(dentry, dir->mnt, mode);
}

/**
 * ccs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return ccs_rmdir_permission(dentry, dir->mnt);
}

/**
 * ccs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return ccs_unlink_permission(dentry, dir->mnt);
}

/**
 * ccs_path_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct path".
 * @dentry:   Pointer to "struct dentry".
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_symlink(const struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	return ccs_symlink_permission(dentry, dir->mnt, old_name);
}

/**
 * ccs_path_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct path".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_rename(const struct path *old_dir,
			   struct dentry *old_dentry,
			   const struct path *new_dir,
			   struct dentry *new_dentry)
{
	return ccs_rename_permission(old_dentry, new_dentry, old_dir->mnt);
}

/**
 * ccs_path_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_link(struct dentry *old_dentry, const struct path *new_dir,
			 struct dentry *new_dentry)
{
	return ccs_link_permission(old_dentry, new_dentry, new_dir->mnt);
}

#else

/**
 * ccs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry,
			   umode_t mode, dev_t dev)
{
	return ccs_mknod_permission(dentry, NULL, mode, dev);
}

/**
 * ccs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			   umode_t mode)
{
	return ccs_mkdir_permission(dentry, NULL, mode);
}

/**
 * ccs_inode_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return ccs_rmdir_permission(dentry, NULL);
}

/**
 * ccs_inode_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return ccs_unlink_permission(dentry, NULL);
}

/**
 * ccs_inode_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct inode".
 * @dentry:   Pointer to "struct dentry".
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
			     const char *old_name)
{
	return ccs_symlink_permission(dentry, NULL, old_name);
}

/**
 * ccs_inode_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct inode".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry)
{
	return ccs_rename_permission(old_dentry, new_dentry, NULL);
}

/**
 * ccs_inode_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @dir:        Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_link(struct dentry *old_dentry, struct inode *dir,
			  struct dentry *new_dentry)
{
	return ccs_link_permission(old_dentry, new_dentry, NULL);
}

/**
 * ccs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_create(struct inode *dir, struct dentry *dentry,
			    umode_t mode)
{
	return ccs_mknod_permission(dentry, NULL, mode, 0);
}

#endif

#ifdef CONFIG_SECURITY_NETWORK

#include <net/sock.h>

/* Structure for remembering an accept()ed socket's status. */
struct ccs_socket_tag {
	struct list_head list;
	struct inode *inode;
	int status;
	struct rcu_head rcu;
};

/*
 * List for managing accept()ed sockets.
 * Since we don't need to keep an accept()ed socket into this list after
 * once the permission was granted, the number of entries in this list is
 * likely small. Therefore, we don't use hash tables.
 */
static LIST_HEAD(ccs_accepted_socket_list);
/* Lock for protecting ccs_accepted_socket_list . */
static DEFINE_SPINLOCK(ccs_accepted_socket_list_lock);

/**
 * ccs_socket_rcu_free - RCU callback for releasing "struct ccs_socket_tag".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void ccs_socket_rcu_free(struct rcu_head *rcu)
{
	struct ccs_socket_tag *ptr = container_of(rcu, typeof(*ptr), rcu);
	kfree(ptr);
}

/**
 * ccs_update_socket_tag - Update tag associated with accept()ed sockets.
 *
 * @inode:  Pointer to "struct inode".
 * @status: New status.
 *
 * Returns nothing.
 *
 * If @status == 0, memory for that socket will be released after RCU grace
 * period.
 */
static void ccs_update_socket_tag(struct inode *inode, int status)
{
	struct ccs_socket_tag *ptr;
	/*
	 * Protect whole section because multiple threads may call this
	 * function with same "sock" via ccs_validate_socket().
	 */
	spin_lock(&ccs_accepted_socket_list_lock);
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_accepted_socket_list, list) {
		if (ptr->inode != inode)
			continue;
		ptr->status = status;
		if (status)
			break;
		list_del_rcu(&ptr->list);
		call_rcu(&ptr->rcu, ccs_socket_rcu_free);
		break;
	}
	rcu_read_unlock();
	spin_unlock(&ccs_accepted_socket_list_lock);
}

/**
 * ccs_validate_socket - Check post accept() permission if needed.
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_validate_socket(struct socket *sock)
{
	struct inode *inode = SOCK_INODE(sock);
	struct ccs_socket_tag *ptr;
	int ret = 0;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_accepted_socket_list, list) {
		if (ptr->inode != inode)
			continue;
		ret = ptr->status;
		break;
	}
	rcu_read_unlock();
	if (ret <= 0)
		/*
		 * This socket is not an accept()ed socket or this socket is
		 * an accept()ed socket and post accept() permission is done.
		 */
		return ret;
	/*
	 * Check post accept() permission now.
	 *
	 * Strictly speaking, we need to pass both listen()ing socket and
	 * accept()ed socket to __ccs_socket_post_accept_permission().
	 * But since socket's family and type are same for both sockets,
	 * passing the accept()ed socket in place for the listen()ing socket
	 * will work.
	 */
	ret = ccs_socket_post_accept_permission(sock, sock);
	/*
	 * If permission was granted, we forget that this is an accept()ed
	 * socket. Otherwise, we remember that this socket needs to return
	 * error for subsequent socketcalls.
	 */
	ccs_update_socket_tag(inode, ret);
	return ret;
}

/**
 * ccs_socket_accept - Check permission for accept().
 *
 * @sock:    Pointer to "struct socket".
 * @newsock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This hook is used for setting up environment for doing post accept()
 * permission check. If dereferencing sock->ops->something() were ordered by
 * rcu_dereference(), we could replace sock->ops with "a copy of original
 * sock->ops with modified sock->ops->accept()" using rcu_assign_pointer()
 * in order to do post accept() permission check before returning to userspace.
 * If we make the copy in security_socket_post_create(), it would be possible
 * to safely replace sock->ops here, but we don't do so because we don't want
 * to allocate memory for sockets which do not call sock->ops->accept().
 * Therefore, we do post accept() permission check upon next socket syscalls
 * rather than between sock->ops->accept() and returning to userspace.
 * This means that if a socket was close()d before calling some socket
 * syscalls, post accept() permission check will not be done.
 */
static int ccs_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct ccs_socket_tag *ptr;
	const int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	/*
	 * Subsequent LSM hooks will receive "newsock". Therefore, I mark
	 * "newsock" as "an accept()ed socket but post accept() permission
	 * check is not done yet" by allocating memory using inode of the
	 * "newsock" as a search key.
	 */
	ptr->inode = SOCK_INODE(newsock);
	ptr->status = 1; /* Check post accept() permission later. */
	spin_lock(&ccs_accepted_socket_list_lock);
	list_add_tail_rcu(&ptr->list, &ccs_accepted_socket_list);
	spin_unlock(&ccs_accepted_socket_list_lock);
	return 0;
}

/**
 * ccs_socket_listen - Check permission for listen().
 *
 * @sock:    Pointer to "struct socket".
 * @backlog: Backlog parameter.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_listen(struct socket *sock, int backlog)
{
	const int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	return ccs_socket_listen_permission(sock);
}

/**
 * ccs_socket_connect - Check permission for connect().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_connect(struct socket *sock, struct sockaddr *addr,
			      int addr_len)
{
	const int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	return ccs_socket_connect_permission(sock, addr, addr_len);
}

/**
 * ccs_socket_bind - Check permission for bind().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_bind(struct socket *sock, struct sockaddr *addr,
			   int addr_len)
{
	const int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	return ccs_socket_bind_permission(sock, addr, addr_len);
}

/**
 * ccs_socket_sendmsg - Check permission for sendmsg().
 *
 * @sock: Pointer to "struct socket".
 * @msg:  Pointer to "struct msghdr".
 * @size: Size of message.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_sendmsg(struct socket *sock, struct msghdr *msg,
			      int size)
{
	const int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	return ccs_socket_sendmsg_permission(sock, msg, size);
}

/**
 * ccs_socket_recvmsg - Check permission for recvmsg().
 *
 * @sock:  Pointer to "struct socket".
 * @msg:   Pointer to "struct msghdr".
 * @size:  Size of message.
 * @flags: Flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			      int size, int flags)
{
	return ccs_validate_socket(sock);
}

/**
 * ccs_socket_getsockname - Check permission for getsockname().
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_getsockname(struct socket *sock)
{
	return ccs_validate_socket(sock);
}

/**
 * ccs_socket_getpeername - Check permission for getpeername().
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_getpeername(struct socket *sock)
{
	return ccs_validate_socket(sock);
}

/**
 * ccs_socket_getsockopt - Check permission for getsockopt().
 *
 * @sock:    Pointer to "struct socket".
 * @level:   Level.
 * @optname: Option's name,
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return ccs_validate_socket(sock);
}

/**
 * ccs_socket_setsockopt - Check permission for setsockopt().
 *
 * @sock:    Pointer to "struct socket".
 * @level:   Level.
 * @optname: Option's name,
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return ccs_validate_socket(sock);
}

/**
 * ccs_socket_shutdown - Check permission for shutdown().
 *
 * @sock: Pointer to "struct socket".
 * @how:  Shutdown mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_shutdown(struct socket *sock, int how)
{
	return ccs_validate_socket(sock);
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * ccs_inode_free_security - Release memory associated with an inode.
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns nothing.
 *
 * We use this hook for releasing memory associated with an accept()ed socket.
 */
static void ccs_inode_free_security(struct inode *inode)
{
	if (inode->i_sb && inode->i_sb->s_magic == SOCKFS_MAGIC)
		ccs_update_socket_tag(inode, 0);
}

#endif

/**
 * ccs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_pivotroot(const struct path *old_path,
			    const struct path *new_path)
{
	return ccs_pivot_root_permission(old_path, new_path);
}

/**
 * ccs_sb_mount - Check permission for mount().
 *
 * @dev_name:  Name of device file.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_mount(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data_page)
{
	return ccs_mount_permission(dev_name, path, type, flags, data_page);
}

/**
 * ccs_sb_umount - Check permission for umount().
 *
 * @mnt:   Pointer to "struct vfsmount".
 * @flags: Unmount flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_umount(struct vfsmount *mnt, int flags)
{
	return ccs_umount_permission(mnt, flags);
}

/**
 * ccs_file_fcntl - Check permission for fcntl().
 *
 * @file: Pointer to "struct file".
 * @cmd:  Command number.
 * @arg:  Value for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return ccs_fcntl_permission(file, cmd, arg);
}

/**
 * ccs_file_ioctl - Check permission for ioctl().
 *
 * @filp: Pointer to "struct file".
 * @cmd:  Command number.
 * @arg:  Value for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_file_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	return ccs_ioctl_permission(filp, cmd, arg);
}

#define MY_HOOK_INIT(HEAD, HOOK)				\
	{ .head = &probe_dummy_security_hook_heads.HEAD,	\
			.hook = { .HEAD = HOOK } }

static struct security_hook_list akari_hooks[] = {
	/* Security context allocator. */
	MY_HOOK_INIT(cred_free, ccs_cred_free),
	MY_HOOK_INIT(cred_prepare, ccs_cred_prepare),
	MY_HOOK_INIT(cred_alloc_blank, ccs_cred_alloc_blank),
	MY_HOOK_INIT(cred_transfer, ccs_cred_transfer),
	MY_HOOK_INIT(task_create, ccs_task_create),
	/* Security context updater for successful execve(). */
	MY_HOOK_INIT(bprm_check_security, ccs_bprm_check_security),
	MY_HOOK_INIT(bprm_committing_creds, ccs_bprm_committing_creds),
	/* Various permission checker. */
	MY_HOOK_INIT(file_open, ccs_file_open),
	MY_HOOK_INIT(file_fcntl, ccs_file_fcntl),
	MY_HOOK_INIT(file_ioctl, ccs_file_ioctl),
	MY_HOOK_INIT(sb_pivotroot, ccs_sb_pivotroot),
	MY_HOOK_INIT(sb_mount, ccs_sb_mount),
	MY_HOOK_INIT(sb_umount, ccs_sb_umount),
#ifdef CONFIG_SECURITY_PATH
	MY_HOOK_INIT(path_mknod, ccs_path_mknod),
	MY_HOOK_INIT(path_mkdir, ccs_path_mkdir),
	MY_HOOK_INIT(path_rmdir, ccs_path_rmdir),
	MY_HOOK_INIT(path_unlink, ccs_path_unlink),
	MY_HOOK_INIT(path_symlink, ccs_path_symlink),
	MY_HOOK_INIT(path_rename, ccs_path_rename),
	MY_HOOK_INIT(path_link, ccs_path_link),
	MY_HOOK_INIT(path_truncate, ccs_path_truncate),
	MY_HOOK_INIT(path_chmod, ccs_path_chmod),
	MY_HOOK_INIT(path_chown, ccs_path_chown),
	MY_HOOK_INIT(path_chroot, ccs_path_chroot),
#else
	MY_HOOK_INIT(inode_mknod, ccs_inode_mknod),
	MY_HOOK_INIT(inode_mkdir, ccs_inode_mkdir),
	MY_HOOK_INIT(inode_rmdir, ccs_inode_rmdir),
	MY_HOOK_INIT(inode_unlink, ccs_inode_unlink),
	MY_HOOK_INIT(inode_symlink, ccs_inode_symlink),
	MY_HOOK_INIT(inode_rename, ccs_inode_rename),
	MY_HOOK_INIT(inode_link, ccs_inode_link),
	MY_HOOK_INIT(inode_create, ccs_inode_create),
	MY_HOOK_INIT(inode_setattr, ccs_inode_setattr),
#endif
	MY_HOOK_INIT(inode_getattr, ccs_inode_getattr),
#ifdef CONFIG_SECURITY_NETWORK
	MY_HOOK_INIT(socket_bind, ccs_socket_bind),
	MY_HOOK_INIT(socket_connect, ccs_socket_connect),
	MY_HOOK_INIT(socket_listen, ccs_socket_listen),
	MY_HOOK_INIT(socket_sendmsg, ccs_socket_sendmsg),
	MY_HOOK_INIT(socket_recvmsg, ccs_socket_recvmsg),
	MY_HOOK_INIT(socket_getsockname, ccs_socket_getsockname),
	MY_HOOK_INIT(socket_getpeername, ccs_socket_getpeername),
	MY_HOOK_INIT(socket_getsockopt, ccs_socket_getsockopt),
	MY_HOOK_INIT(socket_setsockopt, ccs_socket_setsockopt),
	MY_HOOK_INIT(socket_shutdown, ccs_socket_shutdown),
	MY_HOOK_INIT(socket_accept, ccs_socket_accept),
	MY_HOOK_INIT(inode_free_security, ccs_inode_free_security),
#endif
};

static inline void add_hook(struct security_hook_list *hook)
{
	list_add_tail_rcu(&hook->list, hook->head);
}

static void __init swap_hook(struct security_hook_list *hook,
			     union security_list_options *original)
{
	struct list_head *list = hook->head;
	if (list_empty(list)) {
		add_hook(hook);
	} else {
		struct security_hook_list *shp =
			list_last_entry(list, struct security_hook_list, list);
		*original = shp->hook;
		smp_wmb();
		shp->hook = hook->hook;
	}
}

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init ccs_init(void)
{
	int idx;
	struct security_hook_heads *hooks = probe_security_hook_heads();
	if (!hooks)
		goto out;
	for (idx = 0; idx < ARRAY_SIZE(akari_hooks); idx++)
		akari_hooks[idx].head = ((void *) hooks)
			+ ((unsigned long) akari_hooks[idx].head)
			- ((unsigned long) &probe_dummy_security_hook_heads);
	ccsecurity_exports.find_task_by_vpid = probe_find_task_by_vpid();
	if (!ccsecurity_exports.find_task_by_vpid)
		goto out;
	ccsecurity_exports.find_task_by_pid_ns = probe_find_task_by_pid_ns();
	if (!ccsecurity_exports.find_task_by_pid_ns)
		goto out;
	ccsecurity_exports.d_absolute_path = probe_d_absolute_path();
	if (!ccsecurity_exports.d_absolute_path)
		goto out;
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++) {
		INIT_LIST_HEAD(&ccs_cred_security_list[idx]);
		INIT_LIST_HEAD(&ccs_task_security_list[idx]);
	}
	ccs_main_init();
	swap_hook(&akari_hooks[0], &original_cred_free);
	swap_hook(&akari_hooks[1], &original_cred_prepare);
	swap_hook(&akari_hooks[2], &original_cred_alloc_blank);
	for (idx = 3; idx < ARRAY_SIZE(akari_hooks); idx++)
		add_hook(&akari_hooks[idx]);
	printk(KERN_INFO "AKARI: 1.0.36   2017/02/20\n");
	printk(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
out:
	return -EINVAL;
}

module_init(ccs_init);
MODULE_LICENSE("GPL");

/**
 * ccs_used_by_cred - Check whether the given domain is in use or not.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 *
 * Caller holds rcu_read_lock().
 */
bool ccs_used_by_cred(const struct ccs_domain_info *domain)
{
	int idx;
	struct ccs_security *ptr;
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++) {
		struct list_head *list = &ccs_cred_security_list[idx];
		list_for_each_entry_rcu(ptr, list, list) {
			struct ccs_execve *ee = ptr->ee;
			if (ptr->ccs_domain_info == domain ||
			    (ee && ee->previous_domain == domain)) {
				return true;
			}
		}
	}
	return false;
}

/**
 * ccs_add_task_security - Add "struct ccs_security" to list.
 *
 * @ptr:  Pointer to "struct ccs_security".
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void ccs_add_task_security(struct ccs_security *ptr,
				  struct list_head *list)
{
	unsigned long flags;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
}

/**
 * ccs_find_task_security - Find "struct ccs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" on success, &ccs_oom_security on
 * out of memory, &ccs_default_security otherwise.
 *
 * If @task is current thread and "struct ccs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct ccs_security *ccs_find_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr;
	struct list_head *list = &ccs_task_security_list
		[hash_ptr((void *) task, CCS_TASK_SECURITY_HASH_BITS)];
	/* Make sure INIT_LIST_HEAD() in ccs_mm_init() takes effect. */
	while (!list->next);
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->pid != task->pids[PIDTYPE_PID].pid)
			continue;
		rcu_read_unlock();
		/*
		 * Current thread needs to transit from old domain to new
		 * domain before do_execve() succeeds in order to check
		 * permission for interpreters and environment variables using
		 * new domain's ACL rules. The domain transition has to be
		 * visible from other CPU in order to allow interactive
		 * enforcing mode. Also, the domain transition has to be
		 * reverted if do_execve() failed. However, an LSM hook for
		 * reverting domain transition is missing.
		 *
		 * security_prepare_creds() is called from prepare_creds() from
		 * prepare_bprm_creds() from do_execve() before setting
		 * current->in_execve flag, and current->in_execve flag is
		 * cleared by the time next do_execve() request starts.
		 * This means that we can emulate the missing LSM hook for
		 * reverting domain transition, by calling this function from
		 * security_prepare_creds().
		 *
		 * If current->in_execve is not set but ptr->ccs_flags has
		 * CCS_TASK_IS_IN_EXECVE set, it indicates that do_execve()
		 * has failed and reverting domain transition is needed.
		 */
		if (task == current &&
		    (ptr->ccs_flags & CCS_TASK_IS_IN_EXECVE) &&
		    !current->in_execve) {
			ccs_debug_trace("4");
			ccs_clear_execve(-1, ptr);
		}
		return ptr;
	}
	rcu_read_unlock();
	if (task != current) {
		/*
		 * If a thread does nothing after fork(), caller will reach
		 * here because "struct ccs_security" for that thread is not
		 * yet allocated. But that thread is keeping a snapshot of
		 * "struct ccs_security" taken as of ccs_task_create()
		 * associated with that thread's "struct cred".
		 *
		 * Since that snapshot will be used as initial data when that
		 * thread allocates "struct ccs_security" for that thread, we
		 * can return that snapshot rather than &ccs_default_security.
		 *
		 * Since this function is called by only ccs_select_one() and
		 * ccs_read_pid() (via ccs_task_domain() and ccs_task_flags()),
		 * it is guaranteed that caller has called rcu_read_lock()
		 * (via ccs_tasklist_lock()) before finding this thread and
		 * this thread is valid. Therefore, we can do __task_cred(task)
		 * like get_robust_list() does.
		 */
		return ccs_find_cred_security(__task_cred(task));
	}
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &ccs_oom_security;
	}
	*ptr = *ccs_find_cred_security(task->cred);
	/* We can shortcut because task == current. */
	ptr->pid = get_pid(((struct task_struct *) task)->
			   pids[PIDTYPE_PID].pid);
	ptr->cred = NULL;
	ccs_add_task_security(ptr, list);
	return ptr;
}

/**
 * ccs_copy_cred_security - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_copy_cred_security(const struct cred *new,
				  const struct cred *old, gfp_t gfp)
{
	struct ccs_security *old_security = ccs_find_cred_security(old);
	struct ccs_security *new_security =
		kzalloc(sizeof(*new_security), gfp);
	if (!new_security)
		return -ENOMEM;
	*new_security = *old_security;
	new_security->cred = new;
	ccs_add_cred_security(new_security);
	return 0;
}

/**
 * ccs_find_cred_security - Find "struct ccs_security" for given credential.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns pointer to "struct ccs_security" on success, &ccs_default_security
 * otherwise.
 */
static struct ccs_security *ccs_find_cred_security(const struct cred *cred)
{
	struct ccs_security *ptr;
	struct list_head *list = &ccs_cred_security_list
		[hash_ptr((void *) cred, CCS_TASK_SECURITY_HASH_BITS)];
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->cred != cred)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	return &ccs_default_security;
}

/**
 * ccs_task_security_gc - Do garbage collection for "struct task_struct".
 *
 * Returns nothing.
 *
 * Since security_task_free() is missing, I can't release memory associated
 * with "struct task_struct" when a task dies. Therefore, I hold a reference on
 * "struct pid" and runs garbage collection when associated
 * "struct task_struct" has gone.
 */
static void ccs_task_security_gc(void)
{
	static DEFINE_SPINLOCK(lock);
	static atomic_t gc_counter = ATOMIC_INIT(0);
	unsigned int idx;
	/*
	 * If some process is doing execve(), try to garbage collection now.
	 * We should kfree() memory associated with "struct ccs_security"->ee
	 * as soon as execve() has completed in order to compensate for lack of
	 * security_bprm_free() and security_task_free() hooks.
	 *
	 * Otherwise, reduce frequency for performance reason.
	 */
	if (!atomic_read(&ccs_in_execve_tasks) &&
	    atomic_inc_return(&gc_counter) < 1024)
		return;
	if (!spin_trylock(&lock))
		return;
	atomic_set(&gc_counter, 0);
	rcu_read_lock();
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++) {
		struct ccs_security *ptr;
		struct list_head *list = &ccs_task_security_list[idx];
		list_for_each_entry_rcu(ptr, list, list) {
			if (pid_task(ptr->pid, PIDTYPE_PID))
				continue;
			ccs_del_security(ptr);
		}
	}
	rcu_read_unlock();
	spin_unlock(&lock);
}
