/*
 * probe.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Functions in this file are doing runtime address resolution based on byte
 * code comparison in order to allow LKM-based LSM modules to access built-in
 * functions and variables which are not exported to LKMs.
 * Since functions in this file are assuming that using identical source code,
 * identical kernel config and identical compiler generates identical byte code
 * output, functions in this file may not work on some architectures and/or
 * environments.
 *
 * This file is used by AKARI and CaitSith. This file will become unnecessary
 * when LKM-based LSM module comes back and TOMOYO 2.x becomes a LKM-based LSM
 * module.
 */

#include "probe.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

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
 * Returns address of specified function on success, NULL otherwise.
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
		else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
			struct path path = { mnt, dentry };
			file = dentry_open(&path, O_RDONLY, current_cred());
#else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
#endif
		}
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

#if defined(CONFIG_SECURITY_COMPOSER_MAX)

/*
 * Dummy variable for finding location of
 * "struct list_head lsm_hooks[LSM_MAX_HOOKS]".
 */
struct list_head ccs_lsm_hooks[LSM_MAX_HOOKS];

/**
 * ccs_security_bprm_committed_creds - Dummy function which does identical to security_bprm_committed_creds() in security/security.c.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
void ccs_security_bprm_committed_creds(struct linux_binprm *bprm)
{
	do {
		struct security_operations *sop;
		
		list_for_each_entry(sop,
				    &ccs_lsm_hooks[lsm_bprm_committed_creds],
				    list[lsm_bprm_committed_creds])
			sop->bprm_committed_creds(bprm);
	} while (0);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/*
 * Dummy variable for finding address of
 * "struct security_operations *security_ops".
 */
static struct security_operations *ccs_security_ops;

/**
 * ccs_security_file_alloc - Dummy function which does identical to security_file_alloc() in security/security.c.
 *
 * @file: Pointer to "struct file".
 *
 * Returns return value from security_file_alloc().
 */
static int ccs_security_file_alloc(struct file *file)
{
	return ccs_security_ops->file_alloc_security(file);
}

#if defined(CONFIG_ARM)

/**
 * ccs_find_security_ops_on_arm - Find security_ops on ARM.
 *
 * @base: Address of security_file_alloc().
 *
 * Returns address of security_ops on success, NULL otherwise.
 */
static void * __init ccs_find_security_ops_on_arm(unsigned int *base)
{
	static unsigned int *ip4ret;
	int i;
	const unsigned long addr = (unsigned long) &ccs_security_ops;
	unsigned int *ip = (unsigned int *) ccs_security_file_alloc;
	for (i = 0; i < 32; ip++, i++) {
		if (*(ip + 2 + ((*ip & 0xFFF) >> 2)) != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		return &ip4ret;
	}
	ip = (unsigned int *) ccs_security_file_alloc;
	for (i = 0; i < 32; ip++, i++) {
		/*
		 * Find
		 *   ldr r3, [pc, #offset1]
		 *   ldr r3, [r3, #offset2]
		 * sequence.
		 */
		if ((*ip & 0xFFFFF000) != 0xE59F3000 ||
		    (*(ip + 1) & 0xFFFFF000) != 0xE5933000)
			continue;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		ip4ret += (*(ip + 1) & 0xFFF) >> 2;
		if ((unsigned long) ip4ret != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		ip4ret += (*(ip + 1) & 0xFFF) >> 2;
		return &ip4ret;
	}
	return NULL;
}

#endif

#endif

#if defined(CONFIG_ARM) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
/**
 * ccs_find_vfsmount_lock_on_arm - Find vfsmount_lock spinlock on ARM.
 *
 * @ip:   Address of dummy function's entry point.
 * @addr: Address of the variable which is used within @function.
 * @base: Address of function's entry point.
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
static void * __init ccs_find_vfsmount_lock_on_arm(unsigned int *ip,
						   unsigned long addr,
						   unsigned int *base)
{
	int i;
	for (i = 0; i < 32; ip++, i++) {
		static unsigned int *ip4ret;
		if (*(ip + 2 + ((*ip & 0xFFF) >> 2)) != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		return &ip4ret;
	}
	return NULL;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)
	if (*symbol == ' ')
		base = ccs_find_symbol(symbol);
	else
#endif
		base = __symbol_get(symbol);
	if (!base)
		return NULL;
#if defined(CONFIG_ARM) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) && !defined(CONFIG_SECURITY_COMPOSER_MAX)
	if (function == ccs_security_file_alloc)
		return ccs_find_security_ops_on_arm((unsigned int *) base);
#endif
#if defined(CONFIG_ARM) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	return ccs_find_vfsmount_lock_on_arm(function, addr,
					     (unsigned int *) base);
#endif
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

#if defined(CONFIG_SECURITY_COMPOSER_MAX)

static void * __init ccs_find_variable(void *function, unsigned long addr,
				       const char *symbol);

/**
 * ccs_find_lsm_hooks_list - Find address of "struct list_head lsm_hooks[LSM_MAX_HOOKS]".
 *
 * Returns pointer to "struct security_operations" on success, NULL otherwise.
 */
struct list_head * __init ccs_find_lsm_hooks_list(void)
{
	void *cp;
	/* Guess "struct list_head lsm_hooks[LSM_MAX_HOOKS];". */
	cp = ccs_find_variable(ccs_security_bprm_committed_creds,
			       (unsigned long) ccs_lsm_hooks,
			       " security_bprm_committed_creds\n");
	if (!cp) {
		printk(KERN_ERR
		       "Can't resolve security_bprm_committed_creds().\n");
		goto out;
	}
	/* This should be "struct list_head lsm_hooks[LSM_MAX_HOOKS];". */
	cp = (struct list_head *) (*(unsigned long *) cp);
	if (!cp) {
		printk(KERN_ERR "Can't resolve lsm_hooks array.\n");
		goto out;
	}
	printk(KERN_INFO "lsm_hooks=%p\n", cp);
	return cp;
out:
	return NULL;
}

#else

/**
 * ccs_find_security_ops - Find address of "struct security_operations *security_ops".
 *
 * Returns pointer to "struct security_operations" on success, NULL otherwise.
 */
struct security_operations * __init ccs_find_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/* Guess "struct security_operations *security_ops;". */
	cp = ccs_find_variable(ccs_security_file_alloc, (unsigned long)
			       &ccs_security_ops, " security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		return NULL;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		return NULL;
	}
	printk(KERN_INFO "security_ops=%p\n", ptr);
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "No security_operations registered.\n");
		return NULL;
	}
	return ops;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_find_find_task_by_vpid - Find address of find_task_by_vpid().
 *
 * Returns address of find_task_by_vpid() on success, NULL otherwise.
 */
void * __init ccs_find_find_task_by_vpid(void)
{
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = ccs_find_symbol(" find_task_by_vpid\n");
#else
	ptr = __symbol_get("find_task_by_vpid");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_vpid().\n");
		return NULL;
	}
	printk(KERN_INFO "find_task_by_vpid=%p\n", ptr);
	return ptr;
}

/**
 * ccs_find_find_task_by_pid_ns - Find address of find_task_by_pid().
 *
 * Returns address of find_task_by_pid_ns() on success, NULL otherwise.
 */
void * __init ccs_find_find_task_by_pid_ns(void)
{
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = ccs_find_symbol(" find_task_by_pid_ns\n");
#else
	ptr = __symbol_get("find_task_by_pid_ns");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_pid_ns().\n");
		return NULL;
	}
	printk(KERN_INFO "find_task_by_pid_ns=%p\n", ptr);
	return ptr;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t ccs_vfsmount_lock __cacheline_aligned_in_smp =
SPIN_LOCK_UNLOCKED;

static struct list_head *ccs_mount_hashtable;
static int ccs_hash_mask, ccs_hash_bits;

/**
 * hash - Copy of hash() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns hash value.
 */
static inline unsigned long hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long) mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long) dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> ccs_hash_bits);
	return tmp & ccs_hash_mask;
}

/**
 * ccs_lookup_mnt - Dummy function which does identical to lookup_mnt() in fs/namespace.c.
 *
 * @mnt:    Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns pointer to "struct vfsmount".
 */
static struct vfsmount *ccs_lookup_mnt(struct vfsmount *mnt,
				       struct dentry *dentry)
{
	struct list_head *head = ccs_mount_hashtable + hash(mnt, dentry);
	struct list_head *tmp = head;
	struct vfsmount *p, *found = NULL;

	spin_lock(&ccs_vfsmount_lock);
	for (;;) {
		tmp = tmp->next;
		p = NULL;
		if (tmp == head)
			break;
		p = list_entry(tmp, struct vfsmount, mnt_hash);
		if (p->mnt_parent == mnt && p->mnt_mountpoint == dentry) {
			found = mntget(p);
			break;
		}
	}
	spin_unlock(&ccs_vfsmount_lock);
	return found;
}

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * __init ccs_find_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = ccs_find_variable(ccs_lookup_mnt, (unsigned long)
			       &ccs_vfsmount_lock, " lookup_mnt\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve lookup_mnt().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t ccs_vfsmount_lock;

/**
 * ccs_follow_up - Dummy function which does identical to follow_up() in fs/namei.c.
 *
 * @mnt:    Pointer to "struct vfsmount *".
 * @dentry: Pointer to "struct dentry *".
 *
 * Returns 1 if followed up, 0 otehrwise.
 */
static int ccs_follow_up(struct vfsmount **mnt, struct dentry **dentry)
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

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * __init ccs_find_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = ccs_find_variable(ccs_follow_up, (unsigned long)
			       &ccs_vfsmount_lock, "follow_up");
	if (!cp) {
		printk(KERN_ERR "Can't resolve follow_up().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#else

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t ccs_vfsmount_lock;

/**
 * ccs_mnt_pin - Dummy function which does identical to mnt_pin() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns nothing.
 */
static void ccs_mnt_pin(struct vfsmount *mnt)
{
	spin_lock(&ccs_vfsmount_lock);
	mnt->mnt_pinned++;
	spin_unlock(&ccs_vfsmount_lock);
}

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * __init ccs_find_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = ccs_find_variable(ccs_mnt_pin, (unsigned long) &ccs_vfsmount_lock,
			       "mnt_pin");
	if (!cp) {
		printk(KERN_ERR "Can't resolve mnt_pin().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#endif

#else

/*
 * Never mark this variable as __initdata , for this variable might be accessed
 * by caller of ccs_find_vfsmount_lock().
 */
static spinlock_t ccs_vfsmount_lock;

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock.
 */
void * __init ccs_find_vfsmount_lock(void)
{
	return &ccs_vfsmount_lock;
}

#endif

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)

/**
 * ccs_find___d_path - Find address of "__d_path()".
 *
 * Returns address of __d_path() on success, NULL otherwise.
 */
void * __init ccs_find___d_path(void)
{
	void *ptr = ccs_find_symbol(" __d_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve __d_path().\n");
		return NULL;
	}
	printk(KERN_INFO "__d_path=%p\n", ptr);
	return ptr;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)

/**
 * ccs_find_d_absolute_path - Find address of "d_absolute_path()".
 *
 * Returns address of d_absolute_path() on success, NULL otherwise.
 */
void * __init ccs_find_d_absolute_path(void)
{
	void *ptr = ccs_find_symbol(" d_absolute_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve d_absolute_path().\n");
		return NULL;
	}
	printk(KERN_INFO "d_absolute_path=%p\n", ptr);
	return ptr;
}

#endif
