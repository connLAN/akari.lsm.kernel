/*
 * akari-test.c
 *
 * Copyright (C) 2010-2011  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/mount.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#error This module supports only 2.6.0 and later kernels.
#endif
#ifndef CONFIG_SECURITY
#error You must choose CONFIG_SECURITY=y for building this module.
#endif
#ifndef CONFIG_KALLSYMS
#error You must choose CONFIG_KALLSYMS=y for building this module.
#endif
#ifndef CONFIG_PROC_FS
#error You must choose CONFIG_PROC_FS=y for building this module.
#endif
#ifndef CONFIG_MODULES
#error You must choose CONFIG_MODULES=y for building this module.
#endif

#ifndef bool
#define bool _Bool
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

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

#if defined(CONFIG_ARM) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
static int lsm_addr_calculator(struct file *file);
static void * __init ccs_find_security_ops_on_arm(unsigned int *base);
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
#if defined(CONFIG_ARM) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (function == lsm_addr_calculator)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/* Never mark this variable as __initdata . */
static struct security_operations *ccs_security_ops;

/**
 * lsm_addr_calculator - Dummy function which does identical to security_file_alloc() in security/security.c.
 *
 * @file: Pointer to "struct file".
 *
 * Returns return value from security_file_alloc().
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for security_file_alloc() and this function.
 */
static int lsm_addr_calculator(struct file *file)
{
	return ccs_security_ops->file_alloc_security(file);
}

#ifdef CONFIG_ARM
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
	unsigned int *ip = (unsigned int *) lsm_addr_calculator;
	for (i = 0; i < 32; ip++, i++) {
		if (*(ip + 2 + ((*ip & 0xFFF) >> 2)) != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		return &ip4ret;
	}
	ip = (unsigned int *) lsm_addr_calculator;
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

/**
 * ccs_find_find_security_ops - Find address of "struct security_operations *security_ops".
 *
 * Returns pointer to "struct security_operations" on success, NULL otherwise.
 */
static struct security_operations * __init ccs_find_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/* Guess "struct security_operations *security_ops;". */
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

/**
 * ccs_find_find_task_by_pid - Find address of find_task_by_pid().
 *
 * Returns true on success, false otherwise.
 */
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
	printk(KERN_INFO "find_task_by_pid_ns=%p\n", ptr);
	return true;
out:
	return false;
#else
	return true;
#endif
}

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) || LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

/* Never mark this variable as __initdata . */
static spinlock_t ccs_vfsmount_lock __cacheline_aligned_in_smp =
SPIN_LOCK_UNLOCKED;

static struct list_head *mount_hashtable;
static int hash_mask, hash_bits;

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
	tmp = tmp + (tmp >> hash_bits);
	return tmp & hash_mask;
}

/**
 * lsm_lu_mnt - Dummy function which does identical to lookup_mnt() in fs/namespace.c.
 *
 * @mnt:    Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns pointer to "struct vfsmount".
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for lookup_mnt() and this function.
 */
static struct vfsmount *lsm_lu_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	struct list_head *head = mount_hashtable + hash(mnt, dentry);
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

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)

/* Never mark this variable as __initdata . */
static spinlock_t ccs_vfsmount_lock;

/**
 * lsm_flwup - Dummy function which does identical to follow_up() in fs/namei.c.
 *
 * @mnt:    Pointer to "struct vfsmount *".
 * @dentry: Pointer to "struct dentry *".
 *
 * Returns 1 if followed up, 0 otehrwise.
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for follow_up() and this function.
 */
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

/**
 * lsm_pin - Dummy function which does identical to mnt_pin() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns nothing.
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for mnt_pin() and this function.
 */
static void lsm_pin(struct vfsmount *mnt)
{
	spin_lock(&ccs_vfsmount_lock);
	mnt->mnt_pinned++;
	spin_unlock(&ccs_vfsmount_lock);
}

#endif

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns true on success, false otherwise.
 */
static bool __init ccs_find_vfsmount_lock(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = ccs_find_variable(lsm_lu_mnt, (unsigned long) &ccs_vfsmount_lock,
			       " lookup_mnt\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve lookup_mnt().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		goto out;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
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
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
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
	printk(KERN_INFO "__d_path=%p\n", ptr);
	return true;
#endif
}

#else

/**
 * ccs_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns true on success, false otherwise.
 */
static bool __init ccs_find_vfsmount_lock(void)
{
	return true;
}

#endif

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int __init ccs_init(void)
{
	if (!ccs_find_security_ops() || !ccs_find_find_task_by_pid() ||
	    !ccs_find_vfsmount_lock()) {
		printk(KERN_INFO "Sorry, I couldn't guess dependent "
		       "symbols.\n");
		printk(KERN_INFO "I need some changes for supporting your "
		       "environment.\n");
		printk(KERN_INFO "Please contact the author.\n");
		return -EINVAL;
	}
	printk(KERN_INFO "All dependent symbols have been guessed.\n");
	printk(KERN_INFO "Please verify these addresses using System.map for "
	       "this kernel (e.g. /boot/System.map-`uname -r` ).\n");
	printk(KERN_INFO "If these addresses are correct, you can try loading "
	       "AKARI module on this kernel.\n");
	return 0;
}

/**
 * ccs_exit - Exit this module.
 *
 * Returns nothing.
 */
static void ccs_exit(void)
{
}

module_init(ccs_init);
module_exit(ccs_exit);
MODULE_LICENSE("GPL");
