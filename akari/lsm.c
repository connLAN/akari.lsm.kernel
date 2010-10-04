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
static struct security_operations original_security_ops;

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
//#define DEBUG_COUNTER
#ifdef DEBUG_COUNTER
static atomic_t ccs_security_counter[2];
#endif

static void ccs_add_security(struct ccs_security *ptr, const bool is_cred)
{
	unsigned long flags;
	struct ccs_domain_info *domain = ptr->ccs_domain_info;
	if (domain)
		atomic_inc(&domain->users);
#ifdef DEBUG_COUNTER
	atomic_inc(&ccs_security_counter[is_cred]);
	printk(KERN_DEBUG "Add %p (%s=%u)\n", ptr, is_cred ? "cred" : "task",
	       atomic_read(&ccs_security_counter[is_cred]));
#endif
	spin_lock_irqsave(&ccs_security_list_lock, flags);
	list_add_rcu(&ptr->list, &ccs_security_list[is_cred]);
	spin_unlock_irqrestore(&ccs_security_list_lock, flags);
}

void ccs_update_security_domain(struct ccs_domain_info **pdomain,
				struct ccs_domain_info *domain)
{
	if (!pdomain || *pdomain == domain)
		return;
	if (domain)
		atomic_inc(&domain->users);
	if (*pdomain)
		atomic_dec(&(*pdomain)->users);
	*pdomain = domain;
}

static void ccs_clear_execve(int ret, struct ccs_security *security)
{
	struct ccs_execve *ee;
	if (security == &ccs_null_security)
		return;
	ee = security->ee;
	security->ee = NULL;
	if (!ee)
		return;
	ee->reader_idx = ccs_read_lock();
	ccs_finish_execve(ret, ee);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int ccs_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	int rc = ccs_copy_cred_security(new, old, gfp);
	if (rc)
		return rc;
	if (gfp == GFP_KERNEL)
		ccs_task_security_gc();
	rc = original_security_ops.cred_prepare(new, old, gfp);
	if (rc)
		ccs_free_cred_security(new);
	return rc;
}

static void ccs_cred_free(struct cred *cred)
{
	original_security_ops.cred_free(cred);
	ccs_free_cred_security(cred);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

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

static int ccs_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
	int rc = ccs_alloc_cred_security(new, gfp);
	if (rc)
		return rc;
	rc = original_security_ops.cred_alloc_blank(new, gfp);
	if (rc)
		ccs_free_cred_security(new);
	return rc;
}

static void ccs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct ccs_security *new_security;
	struct ccs_security *old_security;
	original_security_ops.cred_transfer(new, old);
	new_security = ccs_find_cred_security(new);
	old_security = ccs_find_cred_security(old);
	if (new_security == &ccs_null_security ||
	    old_security == &ccs_null_security)
		return;
	new_security->ccs_flags = old_security->ccs_flags;
	ccs_update_security_domain(&new_security->ccs_domain_info,
				   old_security->ccs_domain_info);
}

#endif

#else

static void ccs_free_task_security(const struct task_struct *task);

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

static int ccs_task_alloc_security(struct task_struct *p)
{
	int rc = ccs_copy_task_security(p);
	if (rc)
		return rc;
	rc = original_security_ops.task_alloc_security(p);
	if (rc)
		ccs_free_task_security(p);
	return rc;
}

static void ccs_task_free_security(struct task_struct *p)
{
	original_security_ops.task_free_security(p);
	ccs_free_task_security(p);
}

static void ccs_bprm_free_security(struct linux_binprm *bprm)
{
	original_security_ops.bprm_free_security(bprm);
	ccs_clear_execve(-1, ccs_current_security());
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)

static void ccs_bprm_compute_creds(struct linux_binprm *bprm)
{
	original_security_ops.bprm_compute_creds(bprm);
	ccs_clear_execve(0, ccs_current_security());
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

static void ccs_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	original_security_ops.bprm_apply_creds(bprm, unsafe);
	ccs_clear_execve(0, ccs_current_security());
}

#else

static void ccs_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct ccs_security *old_security;
	struct ccs_security *new_security;
	original_security_ops.bprm_committing_creds(bprm);
	old_security = ccs_current_security();
	if (old_security == &ccs_null_security)
		return;
	ccs_clear_execve(0, old_security);
	/* Update current task's cred's domain for future fork(). */
	new_security = ccs_find_cred_security(bprm->cred);
	new_security->ccs_flags = old_security->ccs_flags;
	ccs_update_security_domain(&new_security->ccs_domain_info,
				   old_security->ccs_domain_info);
}

#endif

static int ccs_bprm_check_security(struct linux_binprm *bprm)
{
	int rc;
	struct ccs_security *security = ccs_current_security();
	struct ccs_execve *ee;
	if (security == &ccs_null_security)
		return -ENOMEM;
	ee = security->ee;
	if (!ee) {
		if (!ccs_policy_loaded)
			ccs_load_policy(bprm->filename);
		rc = ccs_start_execve(bprm, &security->ee);
		if (security->ee)
			ccs_read_unlock(security->ee->reader_idx);
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
		rc = ccs_open_permission(bprm->file);
#else
		/* 01 means "read". */
		rc = ccs_open_permission(bprm->file->f_dentry,
					 bprm->file->f_vfsmnt, 01);
#endif
	}
	if (rc)
		return rc;
	return original_security_ops.bprm_check_security(bprm);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

static int ccs_open(struct file *f)
{
	struct dentry *dentry = f->f_path.dentry;
	if (!dentry->d_inode || S_ISDIR(dentry->d_inode->i_mode))
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	/* Don't check read permission here if called from do_execve(). */
	if (current->in_execve)
		return 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ccs_open_permission(f);
#else
	return ccs_open_permission(dentry, f->f_path.mnt, f->f_flags + 1);
#endif
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int ccs_dentry_open(struct file *f, const struct cred *cred)
{
	int rc = ccs_open(f);
	if (rc)
		return rc;
	return original_security_ops.dentry_open(f, cred);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

static int ccs_dentry_open(struct file *f)
{
	int rc = ccs_open(f);
	if (rc)
		return rc;
	return original_security_ops.dentry_open(f);
}

#else

static int ccs_open(struct inode *inode, int mask, struct nameidata *nd)
{
	if (!inode || S_ISDIR(inode->i_mode) || !nd || !nd->dentry
	    || !(mask & (MAY_EXEC | MAY_READ | MAY_WRITE)))
		return 0;
	return ccs_open_permission(nd->dentry, nd->mnt, mask);
}

/* TODO: Use security_file_permission()? */
static int ccs_inode_permission(struct inode *inode, int mask,
				struct nameidata *nd)
{
	int rc = ccs_open(inode, mask, nd);
	if (rc)
		return rc;
	return original_security_ops.inode_permission(inode, mask, nd);
}

#endif

#if defined(CONFIG_SECURITY_PATH)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static int ccs_path_chown(struct path *path, uid_t user, gid_t group)
{
	int rc = ccs_chown_permission(path->dentry, path->mnt, user, group);
	if (rc)
		return rc;
	return original_security_ops.path_chown(path, user, group);
}

static int ccs_path_chmod(struct dentry *dentry, struct vfsmount *vfsmnt,
			  mode_t mode)
{
	int rc = ccs_chmod_permission(dentry, vfsmnt, mode);
	if (rc)
		return rc;
	return original_security_ops.path_chmod(dentry, vfsmnt, mode);
}

static int ccs_path_chroot(struct path *path)
{
	int rc = ccs_chroot_permission(path);
	if (rc)
		return rc;
	return original_security_ops.path_chroot(path);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static int ccs_path_truncate(struct path *path)
{
	int rc = ccs_truncate_permission(path->dentry, path->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_truncate(path);
}
#else
static int ccs_path_truncate(struct path *path, loff_t length,
			     unsigned int time_attrs)
{
	int rc = ccs_truncate_permission(path->dentry, path->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_truncate(path, length, time_attrs);
}
#endif

#endif

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
	return original_security_ops.inode_setattr(dentry, attr);
}

#if defined(CONFIG_SECURITY_PATH)
static int ccs_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			  unsigned int dev)
{
	int rc = ccs_mknod_permission(dir->dentry->d_inode, dentry, dir->mnt, mode,
				      dev);
	if (rc)
		return rc;
	return original_security_ops.path_mknod(dir, dentry, mode, dev);
}

static int ccs_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	int rc = ccs_mkdir_permission(dir->dentry->d_inode, dentry, dir->mnt, mode);
	if (rc)
		return rc;
	return original_security_ops.path_mkdir(dir, dentry, mode);
}

static int ccs_path_rmdir(struct path *dir, struct dentry *dentry)
{
	int rc = ccs_rmdir_permission(dir->dentry->d_inode, dentry, dir->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_rmdir(dir, dentry);
}

static int ccs_path_unlink(struct path *dir, struct dentry *dentry)
{
	int rc = ccs_unlink_permission(dir->dentry->d_inode, dentry, dir->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_unlink(dir, dentry);
}

static int ccs_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	int rc = ccs_symlink_permission(dir->dentry->d_inode, dentry, dir->mnt,
					old_name);
	if (rc)
		return rc;
	return original_security_ops.path_symlink(dir, dentry, old_name);
}

static int ccs_path_rename(struct path *old_dir, struct dentry *old_dentry,
			   struct path *new_dir, struct dentry *new_dentry)
{
	int rc = ccs_rename_permission(old_dir->dentry->d_inode, old_dentry,
				       new_dir->dentry->d_inode, new_dentry,
				       old_dir->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_rename(old_dir, old_dentry, new_dir,
						 new_dentry);
}

static int ccs_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	int rc = ccs_link_permission(old_dentry, new_dir->dentry->d_inode, new_dentry,
				     new_dir->mnt);
	if (rc)
		return rc;
	return original_security_ops.path_link(old_dentry, new_dir,
					       new_dentry);
}
#else
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
			   dev_t dev)
{
	int rc = ccs_mknod_permission(dir, dentry, NULL, mode, dev);
	if (rc)
		return rc;
	return original_security_ops.inode_mknod(dir, dentry, mode, dev);
}
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int rc = ccs_mkdir_permission(dir, dentry, NULL, mode);
	if (rc)
		return rc;
	return original_security_ops.inode_mkdir(dir, dentry, mode);
}
static int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	int rc = ccs_rmdir_permission(dir, dentry, NULL);
	if (rc)
		return rc;
	return original_security_ops.inode_rmdir(dir, dentry);
}
static int ccs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int rc = ccs_unlink_permission(dir, dentry, NULL);
	if (rc)
		return rc;
	return original_security_ops.inode_unlink(dir, dentry);
}

static int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
			     const char *old_name)
{
	int rc = ccs_symlink_permission(dir, dentry, NULL, old_name);
	if (rc)
		return rc;
	return original_security_ops.inode_symlink(dir, dentry, old_name);
}

static int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry)
{
	int rc = ccs_rename_permission(old_dir, old_dentry, new_dir, new_dentry, NULL);
	if (rc)
		return rc;
	return original_security_ops.inode_rename(old_dir, old_dentry, new_dir,
						  new_dentry);
}

static int ccs_inode_link(struct dentry *old_dentry, struct inode *dir,
			  struct dentry *new_dentry)
{
	int rc = ccs_link_permission(old_dentry, dir, new_dentry, NULL);
	if (rc)
		return rc;
	return original_security_ops.inode_link(old_dentry, dir, new_dentry);
}

static int ccs_inode_create(struct inode *dir, struct dentry *dentry,
			    int mode)
{
	int rc = ccs_mknod_permission(dir, dentry, NULL, mode, 0);
	if (rc)
		return rc;
	return original_security_ops.inode_create(dir, dentry, mode);
}

#endif

#ifdef CONFIG_SECURITY_NETWORK
static int ccs_socket_listen(struct socket *sock, int backlog)
{
	int rc = ccs_socket_listen_permission(sock);
	if (rc)
		return rc;
	return original_security_ops.socket_listen(sock, backlog);
}

static int ccs_socket_connect(struct socket *sock, struct sockaddr *addr,
			      int addr_len)
{
	int rc = ccs_socket_connect_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	return original_security_ops.socket_connect(sock, addr, addr_len);
}

static int ccs_socket_bind(struct socket *sock, struct sockaddr *addr,
			   int addr_len)
{
	int rc = ccs_socket_bind_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	return original_security_ops.socket_bind(sock, addr, addr_len);
}

static int ccs_socket_sendmsg(struct socket *sock, struct msghdr *msg,
			      int size)
{
	int rc = ccs_socket_sendmsg_permission(sock, msg, size);
	if (rc)
		return rc;
	return original_security_ops.socket_sendmsg(sock, msg, size);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
static int ccs_sb_pivotroot(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int rc = ccs_pivot_root_permission(old_nd, new_nd);
	if (rc)
		return rc;
	return original_security_ops.sb_pivotroot(old_nd, new_nd);
}

static int ccs_sb_mount(char *dev_name, struct nameidata *nd, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, nd, type, flags, data_page);
	if (rc)
		return rc;
	return original_security_ops.sb_mount(dev_name, nd, type, flags,
					      data_page);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static int ccs_sb_pivotroot(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int rc = ccs_pivot_root_permission(&old_nd->path, &new_nd->path);
	if (rc)
		return rc;
	return original_security_ops.sb_pivotroot(old_nd, new_nd);
}

static int ccs_sb_mount(char *dev_name, struct nameidata *nd, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, &nd->path, type, flags,
				      data_page);
	if (rc)
		return rc;
	return original_security_ops.sb_mount(dev_name, nd, type, flags,
					      data_page);
}
#else
static int ccs_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	int rc = ccs_pivot_root_permission(old_path, new_path);
	if (rc)
		return rc;
	return original_security_ops.sb_pivotroot(old_path, new_path);
}

static int ccs_sb_mount(char *dev_name, struct path *path, char *type,
			unsigned long flags, void *data_page)
{
	int rc = ccs_mount_permission(dev_name, path, type, flags, data_page);
	if (rc)
		return rc;
	return original_security_ops.sb_mount(dev_name, path, type, flags,
					      data_page);
}
#endif

static int ccs_sb_umount(struct vfsmount *mnt, int flags)
{
	int rc = ccs_umount_permission(mnt, flags);
	if (rc)
		return rc;
	return original_security_ops.sb_umount(mnt, flags);
}

static int ccs_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	int rc = ccs_fcntl_permission(file, cmd, arg);
	if (rc)
		return rc;
	return original_security_ops.file_fcntl(file, cmd, arg);
}

static int ccs_file_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	int rc = ccs_ioctl_permission(filp, cmd, arg);
	if (rc)
		return rc;
	return original_security_ops.file_ioctl(filp, cmd, arg);
}

#include <linux/mount.h>
#include <linux/fs_struct.h>

static void *__init ccs_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#else
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#endif
		struct dentry *root;
		struct dentry *dentry;
		if (!mnt)
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
		if (IS_ERR(dentry))
			mntput(mnt);
		else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
		dput(root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		/*
		 * We need to call put_filesystem(fstype); here. However, it is
		 * impossible because this function is used for finding address
		 * of put_filesystem(). Therefore, we embed put_filesystem()
		 * into here.
		 */
		module_put(fstype->owner);
#endif
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = kernel_read(file, offset, buf,
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
	int i;
	const u8 *cp;
	/*
	 * Guess "struct security_operations *security_ops;".
	 * This trick depends on below assumptions.
	 *
	 * (1) Compiler generates identical code for security_file_alloc() and
	 *     lsm_addr_calculator().
	 * (2) ccs_security_ops is found within 128 bytes from
	 *     lsm_addr_calculator, even if additional code (e.g. debug
	 *     symbols) is added.
	 * (3) It is safe to read 128 bytes from lsm_addr_calculator.
	 * (4) ccs_security_ops != Byte code except ccs_security_ops.
	 */
	cp = (const u8 *) lsm_addr_calculator;
	for (i = 0; i < 128; i++) {
		if (sizeof(ccs_security_ops) == sizeof(u32)) {
			if (* (u32 *) cp == (u32) &ccs_security_ops)
				break;
		} else if (sizeof(ccs_security_ops) == sizeof(u64)) {
			if (* (u64 *) cp == (u64) &ccs_security_ops)
				break;
		}
		cp++;
	}
	if (i == 128) {
		printk(KERN_ERR "Can't resolve ccs_security_ops structure.\n");
		goto out;
	}
	cp = (const u8 *) ccs_find_symbol(" security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		goto out;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = * (struct security_operations ***) (cp + i);
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		goto out;
	}
	printk(KERN_INFO "security_ops=%p\n", ptr);
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "No security_operations registered.\n");
		goto out;
	}
	return ops;
 out:
	return NULL;
}

static bool __init ccs_find_sys_getpid(void)
{
	void *ptr;
	ptr = ccs_find_symbol(" sys_getpid\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve sys_getpid().\n");
		goto out;
	}
	ccsecurity_exports.sys_getpid = ptr;
	printk(KERN_INFO "sys_getpid=%p\n", ptr);
	ptr = ccs_find_symbol(" sys_getppid\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve sys_getppid().\n");
		goto out;
	}
	ccsecurity_exports.sys_getppid = ptr;
	printk(KERN_INFO "sys_getppid=%p\n", ptr);
	return true;
 out:
	return false;
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

static bool __init ccs_find_put_filesystem(void)
{
	void *ptr;
	ptr = ccs_find_symbol(" put_filesystem\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve put_filesystem().\n");
		goto out;
	}
	ccsecurity_exports.put_filesystem = ptr;
	printk(KERN_INFO "put_filesystem=%p\n", ptr);
	return true;
 out:
	return false;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	int i;
	const u8 *cp;
	spinlock_t *ptr;
	/*
	 * Guess "spinlock_t vfsmount_lock;".
	 * This trick depends on below assumptions.
	 *
	 * (1) Compiler generates identical code for mnt_pin() and lsm_pin().
	 * (2) ccs_vfsmount_lock is found within 128 bytes from lsm_pin,
	 *     even if additional code (e.g. debug symbols) is added.
	 * (3) It is safe to read 128 bytes from lsm_pin.
	 * (4) ccs_vfsmount_lock != Byte code except ccs_vfsmount_lock.
	 */
	cp = (const u8 *) lsm_pin;
	for (i = 0; i < 128; i++) {
		if (sizeof(void *) == sizeof(u32)) {
			if (* (u32 *) cp == (u32) &ccs_vfsmount_lock)
				break;
		} else if (sizeof(void *) == sizeof(u64)) {
			if (* (u64 *) cp == (u64) &ccs_vfsmount_lock)
				break;
		}
		cp++;
	}
	if (i == 128) {
		printk(KERN_ERR "Can't resolve ccs_vfsmount_lock .\n");
		goto out;
	}
	cp = (const u8 *) __symbol_get("mnt_pin");
	if (!cp) {
		printk(KERN_ERR "Can't resolve mnt_pin().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = * (spinlock_t **) (cp + i);
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
	return true;
#endif
}

static void __init ccs_update_security_ops(struct security_operations *ops)
{
	memmove(&original_security_ops, ops, sizeof(original_security_ops));
	smp_mb();
	synchronize_rcu();
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
#ifdef CONFIG_SECURITY_NETWORK
	ops->socket_bind           = ccs_socket_bind;
	ops->socket_connect        = ccs_socket_connect;
	ops->socket_listen         = ccs_socket_listen;
	ops->socket_sendmsg        = ccs_socket_sendmsg;
#endif
}

static int __init ccs_init(void)
{
	struct security_operations *ops = ccs_find_security_ops();
	if (!ops || !ccs_find_sys_getpid() || !ccs_find_find_task_by_pid() ||
	    !ccs_find_put_filesystem() || !ccs_find_vfsmount_lock() ||
	    !ccs_find___put_task_struct())
		return -EINVAL;
	ccs_main_init();
	ccs_update_security_ops(ops);
	printk(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
}

module_init(ccs_init);
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#undef list_for_each_entry_rcu
#define list_for_each_entry_rcu(pos, head, member)			\
	for (pos = list_entry(rcu_dereference((head)->next),		\
			      typeof(*pos), member);			\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(rcu_dereference(pos->member.next),	\
			      typeof(*pos), member))
#endif

struct ccs_security *ccs_find_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_security_list[0], list) {
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
		/*
		 * Since "struct cred" in "struct linux_binprm" gets scheduled
		 * for destruction but security_cred_free() is not called until
		 * RCU grace period has elapsed, there is no guarantee that
		 * a LSM hook is called before returning to userspace when
		 * do_execve() failed. Therefore, current thread's security
		 * information remains out of dated if do_execve() failed.
		 * If current thread is not marked as "in execve()" but
		 * current thread remembers "struct ccs_execve", that indicates
		 * do_execve() has failed and security information is not yet
		 * updated. Thus, update security information now.
		 */
		if (task == current && !task->in_execve && ptr->ee) {
			printk(KERN_DEBUG
			       "pid=%u: Rolling back to previous domain.\n",
			       task->pid);
			ccs_clear_execve(-1, ptr);
		}
#endif
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &ccs_null_security;
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

static int ccs_copy_cred_security(const struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct ccs_security *old_security = ccs_find_cred_security(old);
	struct ccs_security *new_security = kzalloc(sizeof(*new_security), gfp);
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

static void ccs_rcu_free(struct rcu_head *rcu)
{
	struct ccs_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	struct ccs_execve *ee = ptr->ee;
	ccs_update_security_domain(&ptr->ccs_domain_info, NULL);
	if (ee) {
		ccs_update_security_domain(&ee->previous_domain, NULL);
		kfree(ee->handler_path);
		kfree(ee->tmp);
		kfree(ee->dump.data);
		kfree(ee);
	}
	kfree(ptr);
}

#else

static void ccs_rcu_free(void *arg)
{
	struct ccs_security *ptr = arg;
	struct ccs_execve *ee = ptr->ee;
	ccs_update_security_domain(&ptr->ccs_domain_info, NULL);
	if (ee) {
		ccs_update_security_domain(&ee->previous_domain, NULL);
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

static void ccs_free_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr = ccs_find_task_security(task);
	if (ptr)
		ccs_del_security(ptr, 0);
}

#else

static void ccs_free_cred_security(const struct cred *cred)
{
	struct ccs_security *ptr = ccs_find_cred_security(cred);
	if (ptr)
		ccs_del_security(ptr, 1);
	else
		printk(KERN_WARNING "Security for cred %p not found.\n",
		       cred);
}

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
