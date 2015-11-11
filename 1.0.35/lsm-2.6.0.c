/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.35   2015/11/11
 */

#include "internal.h"
#include "probe.h"

/* Prototype definition. */

/* Dummy security context for avoiding NULL pointer dereference. */
extern struct ccs_security ccs_oom_security;
/* Dummy security context for avoiding NULL pointer dereference. */
extern struct ccs_security ccs_default_security;
/* Dummy marker for calling security_bprm_free(). */
static const unsigned long ccs_bprm_security;

/* For exporting variables and functions. */
struct ccsecurity_exports ccsecurity_exports;
/* Members are updated by loadable kernel module. */
struct ccsecurity_operations ccsecurity_ops;

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10) || defined(atomic_add_return)
	/* Debug counter for detecting "struct ccs_execve" memory leak. */
	static atomic_t ccs_ee_counter = ATOMIC_INIT(0);
	return atomic_add_return(count, &ccs_ee_counter);
#else
	static DEFINE_SPINLOCK(ccs_ee_lock);
	static unsigned int ccs_ee_counter;
	unsigned long flags;
	spin_lock_irqsave(&ccs_ee_lock, flags);
	ccs_ee_counter += count;
	count = ccs_ee_counter;
	spin_unlock_irqrestore(&ccs_ee_lock, flags);
	return count;
#endif
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
	ccs_finish_execve(ret, ee);
}

/**
 * ccs_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_task_alloc_security(struct task_struct *p)
{
	int rc = ccs_alloc_task_security(p);
	if (rc)
		return rc;
	while (!original_security_ops.task_alloc_security);
	rc = original_security_ops.task_alloc_security(p);
	if (rc)
		ccs_free_task_security(p);
	return rc;
}

/**
 * ccs_task_free_security - Release memory for "struct task_struct".
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void ccs_task_free_security(struct task_struct *p)
{
	while (!original_security_ops.task_free_security);
	original_security_ops.task_free_security(p);
	ccs_free_task_security(p);
}

/**
 * ccs_bprm_alloc_security - Allocate memory for "struct linux_binprm".
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_bprm_alloc_security(struct linux_binprm *bprm)
{
	int rc;
	while (!original_security_ops.bprm_alloc_security);
	rc = original_security_ops.bprm_alloc_security(bprm);
	if (bprm->security || rc)
		return rc;
	/*
	 * Update bprm->security to &ccs_bprm_security so that
	 * security_bprm_free() is called even if do_execve() failed at
	 * search_binary_handler() without allocating memory at
	 * security_bprm_alloc(). This trick assumes that active LSM module
	 * does not access bprm->security if that module did not allocate
	 * memory at security_bprm_alloc().
	 */
	bprm->security = (void *) &ccs_bprm_security;
	return 0;
}

/**
 * ccs_bprm_free_security - Release memory for "struct linux_binprm".
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void ccs_bprm_free_security(struct linux_binprm *bprm)
{
	/*
	 * If do_execve() succeeded, bprm->security will be updated to NULL at
	 * security_bprm_compute_creds()/security_bprm_apply_creds() if
	 * bprm->security was set to &ccs_bprm_security at
	 * security_bprm_alloc().
	 *
	 * If do_execve() failed, bprm->security remains at &ccs_bprm_security
	 * if bprm->security was set to &ccs_bprm_security at
	 * security_bprm_alloc().
	 *
	 * And do_execve() does not call security_bprm_free() if do_execve()
	 * failed and bprm->security == NULL. Therefore, do not call
	 * original_security_ops.bprm_free_security() if bprm->security remains
	 * at &ccs_bprm_security .
	 */
	if (bprm->security != &ccs_bprm_security) {
		while (!original_security_ops.bprm_free_security);
		original_security_ops.bprm_free_security(bprm);
	}
	/*
	 * If do_execve() succeeded,
	 * ccs_clear_execve(0, ccs_current_security());
	 * is called before calling below one.
	 * Thus, below call becomes no-op if do_execve() succeeded.
	 */
	ccs_clear_execve(-1, ccs_current_security());
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)

/**
 * ccs_bprm_compute_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void ccs_bprm_compute_creds(struct linux_binprm *bprm)
{
	if (bprm->security == &ccs_bprm_security)
		bprm->security = NULL;
	while (!original_security_ops.bprm_compute_creds);
	original_security_ops.bprm_compute_creds(bprm);
	ccs_clear_execve(0, ccs_current_security());
}

#else

/**
 * ccs_bprm_apply_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm:   Pointer to "struct linux_binprm".
 * @unsafe: Unsafe flag.
 *
 * Returns nothing.
 */
static void ccs_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	if (bprm->security == &ccs_bprm_security)
		bprm->security = NULL;
	while (!original_security_ops.bprm_apply_creds);
	original_security_ops.bprm_apply_creds(bprm, unsafe);
	ccs_clear_execve(0, ccs_current_security());
}

#endif

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
	if (security == &ccs_default_security || security == &ccs_oom_security)
		return -ENOMEM;
	if (!security->ee) {
		int rc;
#ifndef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
		if (!ccs_policy_loaded)
			ccs_load_policy(bprm->filename);
#endif
		rc = ccs_start_execve(bprm, &security->ee);
		if (rc)
			return rc;
	}
	while (!original_security_ops.bprm_check_security);
	return original_security_ops.bprm_check_security(bprm);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct file *f)
{
	return ccs_open_permission(f->f_path.dentry, f->f_path.mnt,
				   f->f_flags + 1);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_dentry_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_dentry_open(struct file *f)
{
	int rc = ccs_open(f);
	if (rc)
		return rc;
	while (!original_security_ops.dentry_open);
	return original_security_ops.dentry_open(f);
}

#else

/**
 * ccs_open - Check permission for open().
 *
 * @inode: Pointer to "struct inode".
 * @mask:  Open mode.
 * @nd:    Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct inode *inode, int mask, struct nameidata *nd)
{
	int flags;
	if (!nd || !nd->dentry)
		return 0;
	/* open_exec() passes MAY_EXEC . */
	if (mask == MAY_EXEC && inode && S_ISREG(inode->i_mode) &&
	    (ccs_current_flags() & CCS_TASK_IS_IN_EXECVE))
		mask = MAY_READ;
	/*
	 * This flags value is passed to ACC_MODE().
	 * ccs_open_permission() for older versions uses old ACC_MODE().
	 */
	switch (mask & (MAY_READ | MAY_WRITE)) {
	case MAY_READ:
		flags = 01;
		break;
	case MAY_WRITE:
		flags = 02;
		break;
	case MAY_READ | MAY_WRITE:
		flags = 03;
		break;
	default:
		return 0;
	}
	return ccs_open_permission(nd->dentry, nd->mnt, flags);
}

/**
 * ccs_inode_permission - Check permission for open().
 *
 * @inode: Pointer to "struct inode".
 * @mask:  Open mode.
 * @nd:    Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Note that this hook is called from permission(), and may not be called for
 * open(). Maybe it is better to use security_file_permission().
 */
static int ccs_inode_permission(struct inode *inode, int mask,
				struct nameidata *nd)
{
	int rc = ccs_open(inode, mask, nd);
	if (rc)
		return rc;
	while (!original_security_ops.inode_permission);
	return original_security_ops.inode_permission(inode, mask, nd);
}

#endif

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
	int rc = 0;
	if (attr->ia_valid & ATTR_UID)
		rc = ccs_chown_permission(dentry, NULL, attr->ia_uid, -1);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = ccs_chown_permission(dentry, NULL, -1, attr->ia_gid);
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = ccs_chmod_permission(dentry, NULL, attr->ia_mode);
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = ccs_truncate_permission(dentry, NULL);
	if (rc)
		return rc;
	while (!original_security_ops.inode_setattr);
	return original_security_ops.inode_setattr(dentry, attr);
}

/**
 * ccs_inode_getattr - Check permission for stat().
 *
 * @mnt:    Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	int rc = ccs_getattr_permission(mnt, dentry);
	if (rc)
		return rc;
	while (!original_security_ops.inode_getattr);
	return original_security_ops.inode_getattr(mnt, dentry);
}

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
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
			   dev_t dev)
{
	int rc = ccs_mknod_permission(dentry, NULL, mode, dev);
	if (rc)
		return rc;
	while (!original_security_ops.inode_mknod);
	return original_security_ops.inode_mknod(dir, dentry, mode, dev);
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
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int rc = ccs_mkdir_permission(dentry, NULL, mode);
	if (rc)
		return rc;
	while (!original_security_ops.inode_mkdir);
	return original_security_ops.inode_mkdir(dir, dentry, mode);
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
	int rc = ccs_rmdir_permission(dentry, NULL);
	if (rc)
		return rc;
	while (!original_security_ops.inode_rmdir);
	return original_security_ops.inode_rmdir(dir, dentry);
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
	int rc = ccs_unlink_permission(dentry, NULL);
	if (rc)
		return rc;
	while (!original_security_ops.inode_unlink);
	return original_security_ops.inode_unlink(dir, dentry);
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
	int rc = ccs_symlink_permission(dentry, NULL, old_name);
	if (rc)
		return rc;
	while (!original_security_ops.inode_symlink);
	return original_security_ops.inode_symlink(dir, dentry, old_name);
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
	int rc = ccs_rename_permission(old_dentry, new_dentry, NULL);
	if (rc)
		return rc;
	while (!original_security_ops.inode_rename);
	return original_security_ops.inode_rename(old_dir, old_dentry, new_dir,
						  new_dentry);
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
	int rc = ccs_link_permission(old_dentry, new_dentry, NULL);
	if (rc)
		return rc;
	while (!original_security_ops.inode_link);
	return original_security_ops.inode_link(old_dentry, dir, new_dentry);
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
			    int mode)
{
	int rc = ccs_mknod_permission(dentry, NULL, mode, 0);
	if (rc)
		return rc;
	while (!original_security_ops.inode_create);
	return original_security_ops.inode_create(dir, dentry, mode);
}

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)

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

#else

/**
 * ccs_socket_rcu_free - RCU callback for releasing "struct ccs_socket_tag".
 *
 * @arg: Pointer to "void".
 *
 * Returns nothing.
 */
static void ccs_socket_rcu_free(void *arg)
{
	struct ccs_socket_tag *ptr = arg;
	kfree(ptr);
}

#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		call_rcu(&ptr->rcu, ccs_socket_rcu_free);
#else
		call_rcu(&ptr->rcu, ccs_socket_rcu_free, ptr);
#endif
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	while (!original_security_ops.socket_accept);
	rc = original_security_ops.socket_accept(sock, newsock);
	if (rc) {
		kfree(ptr);
		return rc;
	}
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	rc = ccs_socket_listen_permission(sock);
	if (rc)
		return rc;
	while (!original_security_ops.socket_listen);
	return original_security_ops.socket_listen(sock, backlog);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	rc = ccs_socket_connect_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	while (!original_security_ops.socket_connect);
	return original_security_ops.socket_connect(sock, addr, addr_len);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	rc = ccs_socket_bind_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	while (!original_security_ops.socket_bind);
	return original_security_ops.socket_bind(sock, addr, addr_len);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	rc = ccs_socket_sendmsg_permission(sock, msg, size);
	if (rc)
		return rc;
	while (!original_security_ops.socket_sendmsg);
	return original_security_ops.socket_sendmsg(sock, msg, size);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_recvmsg);
	return original_security_ops.socket_recvmsg(sock, msg, size, flags);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_getsockname);
	return original_security_ops.socket_getsockname(sock);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_getpeername);
	return original_security_ops.socket_getpeername(sock);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_getsockopt);
	return original_security_ops.socket_getsockopt(sock, level, optname);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_setsockopt);
	return original_security_ops.socket_setsockopt(sock, level, optname);
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
	int rc = ccs_validate_socket(sock);
	if (rc < 0)
		return rc;
	while (!original_security_ops.socket_shutdown);
	return original_security_ops.socket_shutdown(sock, how);
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
	while (!original_security_ops.inode_free_security);
	original_security_ops.inode_free_security(inode);
	if (inode->i_sb && inode->i_sb->s_magic == SOCKFS_MAGIC)
		ccs_update_socket_tag(inode, 0);
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_nd: Pointer to "struct nameidata".
 * @new_nd: Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_pivotroot(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int rc = ccs_pivot_root_permission(old_nd, new_nd);
	if (rc)
		return rc;
	while (!original_security_ops.sb_pivotroot);
	return original_security_ops.sb_pivotroot(old_nd, new_nd);
}

/**
 * ccs_sb_mount - Check permission for mount().
 *
 * @dev_name:  Name of device file.
 * @nd:        Pointer to "struct nameidata".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_mount(char *dev_name, struct nameidata *nd, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, nd, type, flags, data_page);
	if (rc)
		return rc;
	while (!original_security_ops.sb_mount);
	return original_security_ops.sb_mount(dev_name, nd, type, flags,
					      data_page);
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

/**
 * ccs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_nd: Pointer to "struct nameidata".
 * @new_nd: Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_pivotroot(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int rc = ccs_pivot_root_permission(&old_nd->path, &new_nd->path);
	if (rc)
		return rc;
	while (!original_security_ops.sb_pivotroot);
	return original_security_ops.sb_pivotroot(old_nd, new_nd);
}

/**
 * ccs_sb_mount - Check permission for mount().
 *
 * @dev_name:  Name of device file.
 * @nd:        Pointer to "struct nameidata".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_mount(char *dev_name, struct nameidata *nd, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, &nd->path, type, flags,
				      data_page);
	if (rc)
		return rc;
	while (!original_security_ops.sb_mount);
	return original_security_ops.sb_mount(dev_name, nd, type, flags,
					      data_page);
}

#else

/**
 * ccs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	int rc = ccs_pivot_root_permission(old_path, new_path);
	if (rc)
		return rc;
	while (!original_security_ops.sb_pivotroot);
	return original_security_ops.sb_pivotroot(old_path, new_path);
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
static int ccs_sb_mount(char *dev_name, struct path *path, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, path, type, flags, data_page);
	if (rc)
		return rc;
	while (!original_security_ops.sb_mount);
	return original_security_ops.sb_mount(dev_name, path, type, flags,
					      data_page);
}

#endif

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
	int rc = ccs_umount_permission(mnt, flags);
	if (rc)
		return rc;
	while (!original_security_ops.sb_umount);
	return original_security_ops.sb_umount(mnt, flags);
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
	int rc = ccs_fcntl_permission(file, cmd, arg);
	if (rc)
		return rc;
	while (!original_security_ops.file_fcntl);
	return original_security_ops.file_fcntl(file, cmd, arg);
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
	int rc = ccs_ioctl_permission(filp, cmd, arg);
	if (rc)
		return rc;
	while (!original_security_ops.file_ioctl);
	return original_security_ops.file_ioctl(filp, cmd, arg);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21) && defined(CONFIG_SYSCTL_SYSCALL)
int ccs_path_permission(struct ccs_request_info *r, u8 operation,
			const struct ccs_path_info *filename);

/**
 * ccs_prepend - Copy of prepend() in fs/dcache.c.
 *
 * @buffer: Pointer to "struct char *".
 * @buflen: Pointer to int which holds size of @buffer.
 * @str:    String to copy.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * @buffer and @buflen are updated upon success.
 */
static int ccs_prepend(char **buffer, int *buflen, const char *str)
{
	int namelen = strlen(str);
	if (*buflen < namelen)
		return -ENOMEM;
	*buflen -= namelen;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

/**
 * ccs_sysctl_permission - Check permission for sysctl().
 *
 * @table: Pointer to "struct ctl_table".
 * @op:    Operation. (MAY_READ and/or MAY_WRITE)
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sysctl(struct ctl_table *table, int op)
{
	int error;
	struct ccs_path_info buf;
	struct ccs_request_info r;
	int buflen;
	char *buffer;
	int idx;
	while (!original_security_ops.sysctl);
	error = original_security_ops.sysctl(table, op);
	if (error)
		return error;
	op &= MAY_READ | MAY_WRITE;
	if (!op)
		return 0;
	buffer = NULL;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, CCS_MAC_FILE_OPEN)
	    == CCS_CONFIG_DISABLED)
		goto out;
	error = -ENOMEM;
	buflen = 4096;
	buffer = kmalloc(buflen, CCS_GFP_FLAGS);
	if (buffer) {
		char *end = buffer + buflen;
		*--end = '\0';
		buflen--;
		while (table) {
			char num[32];
			const char *sp = table->procname;
			if (!sp) {
				memset(num, 0, sizeof(num));
				snprintf(num, sizeof(num) - 1, "=%d=",
					 table->ctl_name);
				sp = num;
			}
			if (ccs_prepend(&end, &buflen, sp) ||
			    ccs_prepend(&end, &buflen, "/"))
				goto out;
			table = table->parent;
		}
		if (ccs_prepend(&end, &buflen, "proc:/sys"))
			goto out;
		buf.name = ccs_encode(end);
	}
	if (buf.name) {
		ccs_fill_path_info(&buf);
		if (op & MAY_READ)
			error = ccs_path_permission(&r, CCS_TYPE_READ, &buf);
		else
			error = 0;
		if (!error && (op & MAY_WRITE))
			error = ccs_path_permission(&r, CCS_TYPE_WRITE, &buf);
	}
out:
	ccs_read_unlock(idx);
	kfree(buf.name);
	kfree(buffer);
	return error;
}

#endif

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = ccs_##op;

/**
 * ccs_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void __init ccs_update_security_ops(struct security_operations *ops)
{
	/* Security context allocator. */
	swap_security_ops(task_alloc_security);
	swap_security_ops(task_free_security);
	swap_security_ops(bprm_alloc_security);
	swap_security_ops(bprm_free_security);
	/* Security context updater for successful execve(). */
	swap_security_ops(bprm_check_security);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)
	swap_security_ops(bprm_compute_creds);
#else
	swap_security_ops(bprm_apply_creds);
#endif
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	swap_security_ops(dentry_open);
#else
	swap_security_ops(inode_permission);
#endif
	swap_security_ops(file_fcntl);
	swap_security_ops(file_ioctl);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21) && defined(CONFIG_SYSCTL_SYSCALL)
	swap_security_ops(sysctl);
#endif
	swap_security_ops(sb_pivotroot);
	swap_security_ops(sb_mount);
	swap_security_ops(sb_umount);
	swap_security_ops(inode_mknod);
	swap_security_ops(inode_mkdir);
	swap_security_ops(inode_rmdir);
	swap_security_ops(inode_unlink);
	swap_security_ops(inode_symlink);
	swap_security_ops(inode_rename);
	swap_security_ops(inode_link);
	swap_security_ops(inode_create);
	swap_security_ops(inode_setattr);
	swap_security_ops(inode_getattr);
#ifdef CONFIG_SECURITY_NETWORK
	swap_security_ops(socket_bind);
	swap_security_ops(socket_connect);
	swap_security_ops(socket_listen);
	swap_security_ops(socket_sendmsg);
	swap_security_ops(socket_recvmsg);
	swap_security_ops(socket_getsockname);
	swap_security_ops(socket_getpeername);
	swap_security_ops(socket_getsockopt);
	swap_security_ops(socket_setsockopt);
	swap_security_ops(socket_shutdown);
	swap_security_ops(socket_accept);
	swap_security_ops(inode_free_security);
#endif
}

#undef swap_security_ops

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init ccs_init(void)
{
	struct security_operations *ops = probe_security_ops();
	if (!ops)
		goto out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	ccsecurity_exports.find_task_by_vpid = probe_find_task_by_vpid();
	if (!ccsecurity_exports.find_task_by_vpid)
		goto out;
	ccsecurity_exports.find_task_by_pid_ns = probe_find_task_by_pid_ns();
	if (!ccsecurity_exports.find_task_by_pid_ns)
		goto out;
#endif
	ccsecurity_exports.vfsmount_lock = probe_vfsmount_lock();
	if (!ccsecurity_exports.vfsmount_lock)
		goto out;
	ccs_main_init();
	ccs_update_security_ops(ops);
	printk(KERN_INFO "AKARI: 1.0.35   2015/11/11\n");
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
	return false;
}
