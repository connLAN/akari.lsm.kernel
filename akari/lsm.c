/*
 * lsm.c
 *
 * Copyright (C) 2010  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.2   2010/10/25
 */
#include "internal.h"
#include <linux/security.h>
#include <linux/namei.h>

struct cred;

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_null_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

int ccs_start_execve(struct linux_binprm *bprm, struct ccs_execve **eep);
void ccs_finish_execve(int retval, struct ccs_execve *ee);
void ccs_load_policy(const char *filename);
struct ccsecurity_exports ccsecurity_exports;
struct ccsecurity_operations ccsecurity_ops;

static struct security_operations original_security_ops /* = *security_ops; */;

/**
 * lsm_dereference() - Wrapper for reading original_security_ops .
 *
 * Returns &original_security_ops .
 */
static inline struct security_operations *lsm_dereference(void)
{
	/*
	 * Since original_security_ops changes only once, we don't need to
	 * protect it using rcu_read_lock()/rcu_read_unlock(). However, we need
	 * to guarantee that readers see initialized original_security_ops.
	 */
	smp_rmb();
	return &original_security_ops;
}

#if defined(D_PATH_DISCONNECT)
#define CCS_INODE_HOOK_HAS_MNT
#elif defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 25)
#define CCS_INODE_HOOK_HAS_MNT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
static void ccs_task_security_gc(void);
static int ccs_copy_cred_security(const struct cred *new,
				  const struct cred *old, gfp_t gfp);
static struct ccs_security *ccs_find_cred_security(const struct cred *cred);
static void ccs_free_cred_security(const struct cred *cred);
static void (*ccs___put_task_struct) (struct task_struct *t);
#endif

static struct list_head ccs_security_list[2] = {
	LIST_HEAD_INIT(ccs_security_list[0]),
	LIST_HEAD_INIT(ccs_security_list[1]),
};
static DEFINE_SPINLOCK(ccs_security_list_lock);
/* #define DEBUG_COUNTER */
#ifdef DEBUG_COUNTER
static atomic_t ccs_security_counter[2];
#endif

/**
 * ccs_add_security - Add "struct ccs_security" to list.
 *
 * @ptr:     Pointer to "struct ccs_security".
 * @is_cred: True if @ptr is associated with "struct cred *", false if @ptr is
 *           associated with "struct task_struct *".
 *
 * Returns nothing.
 */
static void ccs_add_security(struct ccs_security *ptr, const bool is_cred)
{
	unsigned long flags;
#ifdef DEBUG_COUNTER
	atomic_inc(&ccs_security_counter[is_cred]);
	printk(KERN_DEBUG "Add %p (%s=%u)\n", ptr, is_cred ? "cred" : "task",
	       atomic_read(&ccs_security_counter[is_cred]));
#endif
	spin_lock_irqsave(&ccs_security_list_lock, flags);
	list_add_rcu(&ptr->list, &ccs_security_list[is_cred]);
	spin_unlock_irqrestore(&ccs_security_list_lock, flags);
}

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
	if (security == &ccs_null_security)
		return;
	ee = security->ee;
	security->ee = NULL;
	if (!ee)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/*
	 * Drop refcount on "struct cred" in "struct linux_binprm" and forget
	 * it.
	 */
	put_cred(security->cred);
	security->cred = NULL;
#endif
	ee->reader_idx = ccs_read_lock();
	ccs_finish_execve(ret, ee);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

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
	int rc = ccs_copy_cred_security(new, old, gfp);
	if (rc)
		return rc;
	if (gfp == GFP_KERNEL)
		ccs_task_security_gc();
	rc = lsm_dereference()->cred_prepare(new, old, gfp);
	if (rc)
		ccs_free_cred_security(new);
	return rc;
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
	lsm_dereference()->cred_free(cred);
	ccs_free_cred_security(cred);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

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
	ccs_add_security(new_security, 1);
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
	int rc = ccs_alloc_cred_security(new, gfp);
	if (rc)
		return rc;
	rc = lsm_dereference()->cred_alloc_blank(new, gfp);
	if (rc)
		ccs_free_cred_security(new);
	return rc;
}

/**
 * ccs_cred_transfer - Transfer "struct ccs_security" between credentials.
 *
 * @cred: Pointer to "struct cred".
 * @gfp:  Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static void ccs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct ccs_security *new_security;
	struct ccs_security *old_security;
	lsm_dereference()->cred_transfer(new, old);
	new_security = ccs_find_cred_security(new);
	old_security = ccs_find_cred_security(old);
	if (new_security == &ccs_null_security ||
	    old_security == &ccs_null_security)
		return;
	new_security->ccs_flags = old_security->ccs_flags;
	new_security->ccs_domain_info = old_security->ccs_domain_info;
}

#endif

#else

static void ccs_free_task_security(const struct task_struct *task);

/**
 * ccs_copy_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_copy_task_security(struct task_struct *task)
{
	struct ccs_security *old_security = ccs_current_security();
	struct ccs_security *new_security = kzalloc(sizeof(*new_security),
						    GFP_KERNEL);
	if (!new_security)
		return -ENOMEM;
	*new_security = *old_security;
	new_security->task = task;
	ccs_add_security(new_security, 0);
	return 0;
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
	int rc = ccs_copy_task_security(p);
	if (rc)
		return rc;
	rc = lsm_dereference()->task_alloc_security(p);
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
	lsm_dereference()->task_free_security(p);
	ccs_free_task_security(p);
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
	lsm_dereference()->bprm_free_security(bprm);
	/*
	 * If do_execve() succeeded,
	 * ccs_clear_execve(0, ccs_current_security());
	 * is called before calling below one.
	 * Thus, below call becomes no-op if do_execve() succeeded. 
	 */
	ccs_clear_execve(-1, ccs_current_security());
}

#endif

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
	lsm_dereference()->bprm_compute_creds(bprm);
	ccs_clear_execve(0, ccs_current_security());
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

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
	lsm_dereference()->bprm_apply_creds(bprm, unsafe);
	ccs_clear_execve(0, ccs_current_security());
}

#else

/**
 * ccs_bprm_committing_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void ccs_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct ccs_security *old_security;
	struct ccs_security *new_security;
	lsm_dereference()->bprm_committing_creds(bprm);
	old_security = ccs_current_security();
	if (old_security == &ccs_null_security)
		return;
	ccs_clear_execve(0, old_security);
	/* Update current task's cred's domain for future fork(). */
	new_security = ccs_find_cred_security(bprm->cred);
	new_security->ccs_flags = old_security->ccs_flags;
	new_security->ccs_domain_info = old_security->ccs_domain_info;
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
	int rc;
	struct ccs_security *security = ccs_current_security();
	if (security == &ccs_null_security)
		return -ENOMEM;
	if (!security->cred) {
		if (!ccs_policy_loaded)
			ccs_load_policy(bprm->filename);
		rc = ccs_start_execve(bprm, &security->ee);
		if (security->ee) {
			ccs_read_unlock(security->ee->reader_idx);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
			/*
			 * Get refcount on "struct cred" in
			 * "struct linux_binprm" and remember it.
			 */
			get_cred(bprm->cred);
			security->cred = bprm->cred;
#endif
		}
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
		rc = ccs_open_permission(bprm->file);
#else
		/* 01 means "read". */
		rc = ccs_open_permission(bprm->file->f_dentry,
					 bprm->file->f_vfsmnt, 01);
#endif
	}
	if (rc)
		return rc;
	return lsm_dereference()->bprm_check_security(bprm);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	/* Don't check read permission here if called from do_execve(). */
	if (current->in_execve)
		return 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	return ccs_open_permission(f);
#else
	return ccs_open_permission(f->f_path.dentry, f->f_path.mnt,
				   f->f_flags + 1);
#endif
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

/**
 * ccs_dentry_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_dentry_open(struct file *f, const struct cred *cred)
{
	int rc = ccs_open(f);
	if (rc)
		return rc;
	return lsm_dereference()->dentry_open(f, cred);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

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
	return lsm_dereference()->dentry_open(f);
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
	return lsm_dereference()->inode_permission(inode, mask, nd);
}

#endif

#if defined(CONFIG_SECURITY_PATH)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)

/**
 * ccs_path_chown - Check permission for chown()/chgrp().
 *
 * @path:  Pointer to "struct path".
 * @user:  User ID.
 * @group: Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chown(struct path *path, uid_t user, gid_t group)
{
	int rc = ccs_chown_permission(path->dentry, path->mnt, user, group);
	if (rc)
		return rc;
	return lsm_dereference()->path_chown(path, user, group);
}

/**
 * ccs_path_chmod - Check permission for chmod().
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @mode:   Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chmod(struct dentry *dentry, struct vfsmount *vfsmnt,
			  mode_t mode)
{
	int rc = ccs_chmod_permission(dentry, vfsmnt, mode);
	if (rc)
		return rc;
	return lsm_dereference()->path_chmod(dentry, vfsmnt, mode);
}

/**
 * ccs_path_chroot - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_chroot(struct path *path)
{
	int rc = ccs_chroot_permission(path);
	if (rc)
		return rc;
	return lsm_dereference()->path_chroot(path);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

/**
 * ccs_path_truncate - Check permission for truncate().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_truncate(struct path *path)
{
	int rc = ccs_truncate_permission(path->dentry, path->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_truncate(path);
}

#else

/**
 * ccs_path_truncate - Check permission for truncate().
 *
 * @path:       Pointer to "struct path".
 * @length:     New length.
 * @time_attrs: New time attributes.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_truncate(struct path *path, loff_t length,
			     unsigned int time_attrs)
{
	int rc = ccs_truncate_permission(path->dentry, path->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_truncate(path, length, time_attrs);
}

#endif

#endif

#ifdef CCS_INODE_HOOK_HAS_MNT

/**
 * ccs_inode_setattr - Check permission for chown()/chgrp()/chmod()/truncate().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_setattr(struct dentry *dentry, struct vfsmount *mnt,
			     struct iattr *attr)
{
	int rc = 0;
#if !defined(CONFIG_SECURITY_PATH) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	if (attr->ia_valid & ATTR_UID)
		rc = ccs_chown_permission(dentry, mnt, attr->ia_uid, -1);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = ccs_chown_permission(dentry, mnt, -1, attr->ia_gid);
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = ccs_chmod_permission(dentry, mnt, attr->ia_mode);
#endif
#if !defined(CONFIG_SECURITY_PATH)
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = ccs_truncate_permission(dentry, mnt);
#endif
	if (rc)
		return rc;
	return lsm_dereference()->inode_setattr(dentry, mnt, attr);
}

#else

/**
 * ccs_inode_setattr - Check permission for chown()/chgrp()/chmod()/truncate().
 *
 * @dentry: Pointer to "struct dentry".
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	int rc = 0;
#if !defined(CONFIG_SECURITY_PATH) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	if (attr->ia_valid & ATTR_UID)
		rc = ccs_chown_permission(dentry, NULL, attr->ia_uid, -1);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = ccs_chown_permission(dentry, NULL, -1, attr->ia_gid);
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = ccs_chmod_permission(dentry, NULL, attr->ia_mode);
#endif
#if !defined(CONFIG_SECURITY_PATH)
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = ccs_truncate_permission(dentry, NULL);
#endif
	if (rc)
		return rc;
	return lsm_dereference()->inode_setattr(dentry, attr);
}

#endif

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
	return lsm_dereference()->inode_getattr(mnt, dentry);
}

#if defined(CONFIG_SECURITY_PATH)

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
static int ccs_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			  unsigned int dev)
{
	int rc = ccs_mknod_permission(dir->dentry->d_inode, dentry, dir->mnt,
				      mode, dev);
	if (rc)
		return rc;
	return lsm_dereference()->path_mknod(dir, dentry, mode, dev);
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
static int ccs_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	int rc = ccs_mkdir_permission(dir->dentry->d_inode, dentry, dir->mnt,
				      mode);
	if (rc)
		return rc;
	return lsm_dereference()->path_mkdir(dir, dentry, mode);
}

/**
 * ccs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_rmdir(struct path *dir, struct dentry *dentry)
{
	int rc = ccs_rmdir_permission(dir->dentry->d_inode, dentry, dir->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_rmdir(dir, dentry);
}

/**
 * ccs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_unlink(struct path *dir, struct dentry *dentry)
{
	int rc = ccs_unlink_permission(dir->dentry->d_inode, dentry, dir->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_unlink(dir, dentry);
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
static int ccs_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	int rc = ccs_symlink_permission(dir->dentry->d_inode, dentry, dir->mnt,
					old_name);
	if (rc)
		return rc;
	return lsm_dereference()->path_symlink(dir, dentry, old_name);
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
static int ccs_path_rename(struct path *old_dir, struct dentry *old_dentry,
			   struct path *new_dir, struct dentry *new_dentry)
{
	int rc = ccs_rename_permission(old_dir->dentry->d_inode, old_dentry,
				       new_dir->dentry->d_inode, new_dentry,
				       old_dir->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_rename(old_dir, old_dentry, new_dir,
					      new_dentry);
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
static int ccs_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	int rc = ccs_link_permission(old_dentry, new_dir->dentry->d_inode,
				     new_dentry, new_dir->mnt);
	if (rc)
		return rc;
	return lsm_dereference()->path_link(old_dentry, new_dir, new_dentry);
}

#elif defined(CCS_INODE_HOOK_HAS_MNT)

/**
 * ccs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, int mode, dev_t dev)
{
	int rc = ccs_mknod_permission(dir, dentry, mnt, mode, dev);
	if (rc)
		return rc;
	return lsm_dereference()->inode_mknod(dir, dentry, mnt, mode, dev);
}

/**
 * ccs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, int mode)
{
	int rc = ccs_mkdir_permission(dir, dentry, mnt, mode);
	if (rc)
		return rc;
	return lsm_dereference()->inode_mkdir(dir, dentry, mnt, mode);
}

/**
 * ccs_inode_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt)
{
	int rc = ccs_rmdir_permission(dir, dentry, mnt);
	if (rc)
		return rc;
	return lsm_dereference()->inode_rmdir(dir, dentry, mnt);
}

/**
 * ccs_inode_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_unlink(struct inode *dir, struct dentry *dentry,
			    struct vfsmount *mnt)
{
	int rc = ccs_unlink_permission(dir, dentry, mnt);
	if (rc)
		return rc;
	return lsm_dereference()->inode_unlink(dir, dentry, mnt);
}

/**
 * ccs_inode_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct inode".
 * @dentry:   Pointer to "struct dentry".
 * @mnt:      Pointer to "struct vfsmount". Maybe NULL.
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
			     struct vfsmount *mnt, const char *old_name)
{
	int rc = ccs_symlink_permission(dir, dentry, mnt, old_name);
	if (rc)
		return rc;
	return lsm_dereference()->inode_symlink(dir, dentry, mnt, old_name);
}

/**
 * ccs_inode_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct inode".
 * @old_dentry: Pointer to "struct dentry".
 * @old_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @new_dir:    Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 * @new_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct vfsmount *old_mnt, struct inode *new_dir,
			    struct dentry *new_dentry,
			    struct vfsmount *new_mnt)
{
	int rc = ccs_rename_permission(old_dir, old_dentry, new_dir,
				       new_dentry, new_mnt);
	if (rc)
		return rc;
	return lsm_dereference()->inode_rename(old_dir, old_dentry, old_mnt,
					       new_dir, new_dentry, new_mnt);
}

/**
 * ccs_inode_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @old_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @dir:        Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 * @new_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_link(struct dentry *old_dentry, struct vfsmount *old_mnt,
			  struct inode *dir, struct dentry *new_dentry,
			  struct vfsmount *new_mnt)
{
	int rc = ccs_link_permission(old_dentry, dir, new_dentry, new_mnt);
	if (rc)
		return rc;
	return lsm_dereference()->inode_link(old_dentry, old_mnt, dir,
					     new_dentry, new_mnt);
}

/**
 * ccs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_create(struct inode *dir, struct dentry *dentry,
			    struct vfsmount *mnt, int mode)
{
	int rc = ccs_mknod_permission(dir, dentry, mnt, mode, 0);
	if (rc)
		return rc;
	return lsm_dereference()->inode_create(dir, dentry, mnt, mode);
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
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
			   dev_t dev)
{
	int rc = ccs_mknod_permission(dir, dentry, NULL, mode, dev);
	if (rc)
		return rc;
	return lsm_dereference()->inode_mknod(dir, dentry, mode, dev);
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
	int rc = ccs_mkdir_permission(dir, dentry, NULL, mode);
	if (rc)
		return rc;
	return lsm_dereference()->inode_mkdir(dir, dentry, mode);
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
	int rc = ccs_rmdir_permission(dir, dentry, NULL);
	if (rc)
		return rc;
	return lsm_dereference()->inode_rmdir(dir, dentry);
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
	int rc = ccs_unlink_permission(dir, dentry, NULL);
	if (rc)
		return rc;
	return lsm_dereference()->inode_unlink(dir, dentry);
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
	int rc = ccs_symlink_permission(dir, dentry, NULL, old_name);
	if (rc)
		return rc;
	return lsm_dereference()->inode_symlink(dir, dentry, old_name);
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
	int rc = ccs_rename_permission(old_dir, old_dentry, new_dir,
				       new_dentry, NULL);
	if (rc)
		return rc;
	return lsm_dereference()->inode_rename(old_dir, old_dentry, new_dir,
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
	int rc = ccs_link_permission(old_dentry, dir, new_dentry, NULL);
	if (rc)
		return rc;
	return lsm_dereference()->inode_link(old_dentry, dir, new_dentry);
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
	int rc = ccs_mknod_permission(dir, dentry, NULL, mode, 0);
	if (rc)
		return rc;
	return lsm_dereference()->inode_create(dir, dentry, mode);
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

/* List for managing accept()ed sockets. */
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
	rc = lsm_dereference()->socket_accept(sock, newsock);
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
	return lsm_dereference()->socket_listen(sock, backlog);
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
	return lsm_dereference()->socket_connect(sock, addr, addr_len);
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
	return lsm_dereference()->socket_bind(sock, addr, addr_len);
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
	return lsm_dereference()->socket_sendmsg(sock, msg, size);
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
	return lsm_dereference()->socket_recvmsg(sock, msg, size, flags);
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
	return lsm_dereference()->socket_getsockname(sock);
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
	return lsm_dereference()->socket_getpeername(sock);
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
	return lsm_dereference()->socket_getsockopt(sock, level, optname);
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
	return lsm_dereference()->socket_setsockopt(sock, level, optname);
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
	return lsm_dereference()->socket_shutdown(sock, how);
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
	lsm_dereference()->inode_free_security(inode);
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
	return lsm_dereference()->sb_pivotroot(old_nd, new_nd);
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
	return lsm_dereference()->sb_mount(dev_name, nd, type, flags,
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
	return lsm_dereference()->sb_pivotroot(old_nd, new_nd);
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
	return lsm_dereference()->sb_mount(dev_name, nd, type, flags,
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
	return lsm_dereference()->sb_pivotroot(old_path, new_path);
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
	return lsm_dereference()->sb_mount(dev_name, path, type, flags,
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
	return lsm_dereference()->sb_umount(mnt, flags);
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
	return lsm_dereference()->file_fcntl(file, cmd, arg);
}

/**
 * ccs_file_ioctl - Check permission for ioctl().
 *
 * @file: Pointer to "struct file".
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
	return lsm_dereference()->file_ioctl(filp, cmd, arg);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

#include <linux/mount.h>
#include <linux/fs_struct.h>

/**
 * ccs_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int __init ccs_kernel_read(struct file *file, unsigned long offset,
				  char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * ccs_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find.
 *
 * Returns address if specified function on success, NULL otherwise.
 */
static void *__init ccs_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = ccs_kernel_read(file, offset, buf,
					      PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}

#endif

/**
 * ccs_find_variable - Find variable's address using dummy.
 *
 * @function: Pointer to dummy function's entry point.
 * @addr:     Address of the variable which is used within @function.
 * @symbol:   Name of symbol to resolve.
 *
 * This trick depends on below assumptions.
 *
 * (1) @addr is found within 128 bytes from @function, even if additional
 *     code (e.g. debug symbols) is added.
 * (2) It is safe to read 128 bytes from @function.
 * (3) @addr != Byte code except @addr.
 */
static void * __init ccs_find_variable(void *function, unsigned long addr,
				       const char *symbol)
{
	int i;
	u8 *base;
	u8 *cp = function;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (*symbol == ' ')
		base = ccs_find_symbol(symbol);
	else
#endif
		base = __symbol_get(symbol);
	if (!base)
		return NULL;
	/* First, assume absolute adressing mode is used. */
	for (i = 0; i < 128; i++) {
		if (*(unsigned long *) cp == addr)
			return base + i;
		cp++;
	}
	/* Next, assume PC-relative addressing mode is used. */
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (cp + sizeof(int) + *(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp += sizeof(int) + *(int *) cp;
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (long) (*(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp = (void *) (long) (*(int *) cp);
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/* Never mark this variable as __initdata . */
static struct security_operations *ccs_security_ops;

/* Never mark this function as __init . */
static int lsm_addr_calculator(struct file *file)
{
	return ccs_security_ops->file_alloc_security(file);
}

#endif

static struct security_operations * __init ccs_find_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/*
	 * Guess "struct security_operations *security_ops;".
	 * This trick assumes that compiler generates identical code for
	 * security_file_alloc() and lsm_addr_calculator().
	 */
	cp = ccs_find_variable(lsm_addr_calculator, (unsigned long)
			       &ccs_security_ops, " security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		goto out;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		goto out;
	}
	printk(KERN_INFO "&security_ops=%p\n", ptr);
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "No security_operations registered.\n");
		goto out;
	}
	/*
	 * Save original pointers and issue memory barrier. Readers must use
	 * lsm_dereference()->something() in order to guarantee that readers
	 * see original pointers saved here.
	 */
	original_security_ops = *ops;
	smp_wmb();
	return ops;
out:
	return NULL;
}

static bool __init ccs_find_find_task_by_pid(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = ccs_find_symbol(" find_task_by_vpid\n");
#else
	ptr = __symbol_get("find_task_by_vpid");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_vpid().\n");
		goto out;
	}
	ccsecurity_exports.find_task_by_vpid = ptr;
	printk(KERN_INFO "find_task_by_vpid=%p\n", ptr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = ccs_find_symbol(" find_task_by_pid_ns\n");
#else
	ptr = __symbol_get("find_task_by_pid_ns");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_pid_ns().\n");
		goto out;
	}
	ccsecurity_exports.find_task_by_pid_ns = ptr;
	printk(KERN_INFO "find_task_by_pid_ns=%p\n", ptr);
	return true;
out:
	return false;
#else
	return true;
#endif
}

static bool __init ccs_find___put_task_struct(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	void *ptr;
	ptr = ccs_find_symbol(" __put_task_struct\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve __put_task_struct().\n");
		goto out;
	}
	ccs___put_task_struct = ptr;
	printk(KERN_INFO "__put_task_struct=%p\n", ptr);
	return true;
out:
	return false;
#else
	return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)

/* Never mark this variable as __initdata . */
static spinlock_t ccs_vfsmount_lock;

/* Never mark this function as __init . */
static int lsm_flwup(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *parent;
	struct dentry *mountpoint;
	spin_lock(&ccs_vfsmount_lock);
	parent = (*mnt)->mnt_parent;
	if (parent == *mnt) {
		spin_unlock(&ccs_vfsmount_lock);
		return 0;
	}
	mntget(parent);
	mountpoint = dget((*mnt)->mnt_mountpoint);
	spin_unlock(&ccs_vfsmount_lock);
	dput(*dentry);
	*dentry = mountpoint;
	mntput(*mnt);
	*mnt = parent;
	return 1;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

/* Never mark this variable as __initdata . */
static spinlock_t ccs_vfsmount_lock;

/* Never mark this function as __init . */
static void lsm_pin(struct vfsmount *mnt)
{
	spin_lock(&ccs_vfsmount_lock);
	mnt->mnt_pinned++;
	spin_lock(&ccs_vfsmount_lock);
}

#endif

static bool __init ccs_find_vfsmount_lock(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
	void *cp;
	spinlock_t *ptr;
	/*
	 * Guess "spinlock_t vfsmount_lock;".
	 * This trick assumes that compiler generates identical code for
	 * follow_up() and lsm_flwup().
	 */
	cp = ccs_find_variable(lsm_flwup, (unsigned long) &ccs_vfsmount_lock,
			       "follow_up");
	if (!cp) {
		printk(KERN_ERR "Can't resolve follow_up().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		goto out;
	}
	ccsecurity_exports.vfsmount_lock = ptr;
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	void *cp;
	spinlock_t *ptr;
	/*
	 * Guess "spinlock_t vfsmount_lock;".
	 * This trick assumes that compiler generates identical code for
	 * mnt_pin() and lsm_pin().
	 */
	cp = ccs_find_variable(lsm_pin, (unsigned long) &ccs_vfsmount_lock,
			       "mnt_pin");
	if (!cp) {
		printk(KERN_ERR "Can't resolve mnt_pin().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		goto out;
	}
	ccsecurity_exports.vfsmount_lock = ptr;
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#else
	void *ptr = ccs_find_symbol(" __d_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve __d_path().\n");
		return false;
	}
	ccsecurity_exports.__d_path = ptr;
	printk(KERN_INFO "__d_path=%p\n", ptr);
	return true;
#endif
}

static void __init ccs_update_security_ops(struct security_operations *ops)
{
	/* Security context allocator. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	ops->cred_prepare          = ccs_cred_prepare;
	ops->cred_free             = ccs_cred_free;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	ops->cred_alloc_blank      = ccs_cred_alloc_blank;
	ops->cred_transfer         = ccs_cred_transfer;
#endif
#else
	ops->task_alloc_security   = ccs_task_alloc_security;
	ops->task_free_security    = ccs_task_free_security;
	ops->bprm_free_security    = ccs_bprm_free_security;
#endif
	/* Security context updater for successful execve(). */
	ops->bprm_check_security   = ccs_bprm_check_security;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)
	ops->bprm_compute_creds    = ccs_bprm_compute_creds;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	ops->bprm_apply_creds      = ccs_bprm_apply_creds;
#else
	ops->bprm_committing_creds = ccs_bprm_committing_creds;
#endif
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	ops->dentry_open           = ccs_dentry_open;
#else
	ops->inode_permission      = ccs_inode_permission;
#endif
	ops->file_fcntl            = ccs_file_fcntl;
	ops->file_ioctl            = ccs_file_ioctl;
	ops->sb_pivotroot          = ccs_sb_pivotroot;
	ops->sb_mount              = ccs_sb_mount;
	ops->sb_umount             = ccs_sb_umount;
#if defined(CONFIG_SECURITY_PATH)
	ops->path_mknod            = ccs_path_mknod;
	ops->path_mkdir            = ccs_path_mkdir;
	ops->path_rmdir            = ccs_path_rmdir;
	ops->path_unlink           = ccs_path_unlink;
	ops->path_symlink          = ccs_path_symlink;
	ops->path_rename           = ccs_path_rename;
	ops->path_link             = ccs_path_link;
	ops->path_truncate         = ccs_path_truncate;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	ops->path_chmod            = ccs_path_chmod;
	ops->path_chown            = ccs_path_chown;
	ops->path_chroot           = ccs_path_chroot;
#endif
#else
	ops->inode_mknod           = ccs_inode_mknod;
	ops->inode_mkdir           = ccs_inode_mkdir;
	ops->inode_rmdir           = ccs_inode_rmdir;
	ops->inode_unlink          = ccs_inode_unlink;
	ops->inode_symlink         = ccs_inode_symlink;
	ops->inode_rename          = ccs_inode_rename;
	ops->inode_link            = ccs_inode_link;
	ops->inode_create          = ccs_inode_create;
#endif
	ops->inode_setattr         = ccs_inode_setattr;
	ops->inode_getattr         = ccs_inode_getattr;
#ifdef CONFIG_SECURITY_NETWORK
	ops->socket_bind           = ccs_socket_bind;
	ops->socket_connect        = ccs_socket_connect;
	ops->socket_listen         = ccs_socket_listen;
	ops->socket_sendmsg        = ccs_socket_sendmsg;
	ops->socket_recvmsg        = ccs_socket_recvmsg;
	ops->socket_getsockname    = ccs_socket_getsockname;
	ops->socket_getpeername    = ccs_socket_getpeername;
	ops->socket_getsockopt     = ccs_socket_getsockopt;
	ops->socket_setsockopt     = ccs_socket_setsockopt;
	ops->socket_shutdown       = ccs_socket_shutdown;
	ops->socket_accept         = ccs_socket_accept;
	ops->inode_free_security   = ccs_inode_free_security;
#endif
}

static int __init ccs_init(void)
{
	struct security_operations *ops = ccs_find_security_ops();
	if (!ops || !ccs_find_find_task_by_pid() ||
	    !ccs_find_vfsmount_lock() || !ccs_find___put_task_struct())
		return -EINVAL;
	ccs_main_init();
	ccs_update_security_ops(ops);
	printk(KERN_INFO "AKARI: 1.0.2   2010/10/25\n");
	printk(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
}

module_init(ccs_init);
MODULE_LICENSE("GPL");

/**
 * ccs_domain_in_use - Check whether the given domain is in use or not.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 */
bool ccs_domain_in_use(const struct ccs_domain_info *domain)
{
	u8 i;
	struct ccs_security *ptr;
	rcu_read_lock();
	for (i = 0; i < 2; i++) {
		struct list_head *list = &ccs_security_list[i];
		list_for_each_entry_rcu(ptr, list, list) {
			struct ccs_execve *ee = ptr->ee;
			if (ptr->ccs_domain_info == domain ||
			    (ee && ee->previous_domain == domain))
				goto found;
		}
	}
found:
	rcu_read_unlock();
	return i < 2;
}

/**
 * ccs_find_task_security - Find "struct ccs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" on success, &ccs_null_security
 * otherwise.
 *
 * If @task is current thread and "struct ccs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct ccs_security *ccs_find_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_security_list[0], list) {
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
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
		 * When do_execve() failed, "struct cred" in
		 * "struct linux_binprm" is scheduled for destruction.
		 * But current thread returns to userspace without waiting for
		 * destruction. The security_cred_free() LSM hook is called
		 * after an RCU grace period has elapsed. Since some CPU may be
		 * doing long long RCU read side critical section, there is
		 * no guarantee that security_cred_free() is called before
		 * current thread again calls do_execve().
		 *
		 * To be able to revert domain transition before processing
		 * next do_execve() request, current thread gets a refcount on
		 * "struct cred" in "struct linux_binprm" and memorizes it.
		 * Current thread drops the refcount and forgets it when
		 * do_execve() succeeded.
		 *
		 * Therefore, if current thread hasn't forgotten it and
		 * current thread is the last one using that "struct cred",
		 * it indicates that do_execve() has failed and reverting
		 * domain transition is needed.
		 */
		if (task == current && ptr->cred &&
		    atomic_read(&ptr->cred->usage) == 1) {
			printk(KERN_DEBUG
			       "pid=%u: Reverting domain transition because "
			       "do_execve() has failed.\n", task->pid);
			ccs_clear_execve(-1, ptr);
		}
#endif
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &ccs_null_security;
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &ccs_null_security;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	*ptr = *ccs_find_cred_security(task->cred);
#else
	*ptr = ccs_null_security;
#endif
	get_task_struct((struct task_struct *) task);
	ptr->task = (struct task_struct *) task;
	/* ptr->cred may point to garbage. I need to explicitly clear. */
	ptr->cred = NULL;
	ccs_add_security(ptr, 0);
	return ptr;
}

struct ccs_domain_info *ccs_read_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr = ccs_find_task_security(task);
	if (!ptr)
		return NULL;
	return ptr->ccs_domain_info;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

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
	ccs_add_security(new_security, 1);
	return 0;
}

static struct ccs_security *ccs_find_cred_security(const struct cred *cred)
{
	struct ccs_security *ptr;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_security_list[1], list) {
		if (ptr->cred != cred)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	return &ccs_null_security;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/*
	 * If this security context was used by "struct task_struct" and
	 * remembers "struct cred" in "struct linux_binprm", it indicates that
	 * that "struct task_struct" exited immediately after do_execve() has
	 * failed.
	 */
	if (ptr->task && ptr->cred) {
		/*
		printk(KERN_DEBUG
		       "Dropping refcount on \"struct cred\" in "
		       "\"struct linux_binprm\" because some "
		       "\"struct task_struct\" has exit()ed immediately after "
		       "do_execve() has failed.\n");
		*/
		put_cred(ptr->cred);
	}
#endif
	if (ee) {
		/*
		printk(KERN_DEBUG
		       "Releasing memory in \"struct ccs_execve\" because "
		       "some \"struct task_struct\" has exit()ed immediately "
		       "after do_execve() has failed.\n");
		*/
		kfree(ee->handler_path);
		kfree(ee->tmp);
		kfree(ee->dump.data);
		kfree(ee);
	}
	kfree(ptr);
}

#else

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @arg: Pointer to "void".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(void *arg)
{
	struct ccs_security *ptr = arg;
	struct ccs_execve *ee = ptr->ee;
	if (ee) {
		kfree(ee->handler_path);
		kfree(ee->tmp);
		kfree(ee->dump.data);
		kfree(ee);
	}
	kfree(ptr);
}

#endif

static void ccs_del_security(struct ccs_security *ptr, const bool is_cred)
{
	unsigned long flags;
	if (ptr == &ccs_null_security)
		return;
	spin_lock_irqsave(&ccs_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&ccs_security_list_lock, flags);
#ifdef DEBUG_COUNTER
	atomic_dec(&ccs_security_counter[is_cred]);
	printk(KERN_DEBUG "Del %p (%s=%u)\n", ptr, is_cred ? "cred" : "task",
	       atomic_read(&ccs_security_counter[is_cred]));
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	call_rcu(&ptr->rcu, ccs_rcu_free);
#else
	call_rcu(&ptr->rcu, ccs_rcu_free, ptr);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

/**
 * ccs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void ccs_free_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr = ccs_find_task_security(task);
	if (ptr)
		ccs_del_security(ptr, 0);
}

#else

/**
 * ccs_free_cred_security - Release memory associated with "struct cred".
 *
 * @cred: Pointer to "struct task_cred".
 *
 * Returns nothing.
 */
static void ccs_free_cred_security(const struct cred *cred)
{
	struct ccs_security *ptr = ccs_find_cred_security(cred);
	if (ptr)
		ccs_del_security(ptr, 1);
	else
		printk(KERN_WARNING "Security for cred %p not found.\n",
		       cred);
}

/**
 * ccs_task_security_gc - Do garbage collection for "struct task_struct".
 *
 * Returns nothing.
 *
 * Since security_task_free_security() is missing, I can't release memory
 * associated with "struct task_struct" when a task dies. Therefore, I hold
 * a reference on "struct taskstruct" and runs garbage collection when I became
 * the last user who refers that "struct task_struct".
 */
static void ccs_task_security_gc(void)
{
	static DEFINE_MUTEX(lock);
	struct ccs_security *ptr;
	if (!mutex_trylock(&lock))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_security_list[0], list) {
		struct task_struct *task = ptr->task;
		if (need_resched()) {
			rcu_read_unlock();
			cond_resched();
			rcu_read_lock();
			if (signal_pending(current))
				break;
		}
		/* Am I the last one using this task? */
		if (atomic_read(&task->usage) != 1)
			continue;
		/*
		 * We need to call put_task_struct(task); here. However, since
		 * put_task_struct() is an inlined function which calls
		 * __put_task_struct() and __put_task_struct() is not exported,
		 * we embed put_task_struct() into here.
		 */
		atomic_dec(&task->usage);
		ccs___put_task_struct(task);
		ccs_del_security(ptr, 0);
	}
	rcu_read_unlock();
	mutex_unlock(&lock);
	return;
}

#endif