/*
 * kpr.c
 *
 * Copyright (C) 2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 0.1   2013/08/02
 */

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <asm/uaccess.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#error This module supports only 2.6.0 and later kernels.
#endif
#ifndef CONFIG_SECURITY
#error You must choose CONFIG_SECURITY=y for building this module.
#endif
#ifndef CONFIG_SECURITY_NETWORK
#error You must choose CONFIG_SECURITY_NETWORK=y for building this module.
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_init(mutex) init_MUTEX(mutex)
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock(mutex) down(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define mutex_trylock(mutex) (!down_trylock(mutex))
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 13)
#define kstrdup(str, flags) ({					\
			size_t size = strlen((str)) + 1;	\
			void *ret = kmalloc(size, (flags));	\
			if (ret)				\
				memmove(ret, (str), size);	\
			ret; })
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
#define kzalloc(size, flags) ({					\
			void *ret = kmalloc((size), (flags));	\
			if (ret)				\
				memset(ret, 0, (size));		\
			ret; })
#endif

#include "probe.h"

/* For importing variables and functions. */
struct ccsecurity_exports {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	char * (*d_absolute_path) (const struct path *, char *, int);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	typeof(__d_path) (*__d_path);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spinlock_t *vfsmount_lock;
#endif
} ccsecurity_exports;

/* Max length of a line. */
#define MAX_LINE_LEN 16384

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

/* Port numbers which the whitelist exists. */
static unsigned long reserved_port_map[65536 / BITS_PER_LONG];

/* Whitelist element. */
struct reserved_port_entry {
	struct list_head list;
	const char *exe;
	u16 port;
};
/* List of whitelist elements. */ 
static LIST_HEAD(reserved_port_list);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)

/**
 * kpr_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_lock(void)
{
	/* dcache_lock is locked by __d_path(). */
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * kpr_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	/* dcache_lock is unlocked by __d_path(). */
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 36)

/**
 * kpr_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * kpr_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	spin_unlock(&dcache_lock);
}

#elif defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

/**
 * kpr_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 *
 * Original unambiguous-__d_path.diff in patches.apparmor.tar.bz2 inversed the
 * order of holding dcache_lock and vfsmount_lock. That patch was applied on
 * (at least) SUSE 11.1 and Ubuntu 8.10 and Ubuntu 9.04 kernels.
 *
 * However, that patch was updated to use original order and the updated patch
 * is applied to (as far as I know) only SUSE kernels.
 *
 * Therefore, I need to use original order for SUSE 11.1 kernels and inversed
 * order for other kernels. I detect it by checking D_PATH_DISCONNECT and
 * CONFIG_SUSE_KERNEL. I don't know whether other distributions are using the
 * updated patch or not. If you got deadlock, check fs/dcache.c for locking
 * order, and add " && 0" to this "#elif " block if fs/dcache.c uses original
 * order.
 */
static inline void kpr_realpath_lock(void)
{
	spin_lock(ccsecurity_exports.vfsmount_lock);
	spin_lock(&dcache_lock);
}

/**
 * kpr_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(ccsecurity_exports.vfsmount_lock);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)

/**
 * kpr_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(ccsecurity_exports.vfsmount_lock);
}

/**
 * kpr_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_unlock(void)
{
	spin_unlock(ccsecurity_exports.vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#else

/**
 * kpr_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_lock(void)
{
	spin_lock(&dcache_lock);
}

/**
 * kpr_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void kpr_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
}

#endif

/**
 * kpr_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Caller holds the dcache_lock and vfsmount_lock.
 * Based on __d_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 */
static char *kpr_get_absolute_path(struct path *path, char * const buffer,
				   const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		pos = ccsecurity_exports.d_absolute_path(path, buffer,
							 buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = path->dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	/*
	 * __d_path() will start returning NULL by backporting commit 02125a82
	 * "fix apparmor dereferencing potentially freed dentry, sanitize
	 * __d_path() API".
	 *
	 * Unfortunately, __d_path() after applying that commit always returns
	 * NULL when root is empty. d_absolute_path() is provided for TOMOYO
	 * 2.x and AppArmor but TOMOYO 1.x does not use it, for TOMOYO 1.x
	 * might be built as a loadable kernel module and there is no warrantee
	 * that TOMOYO 1.x is recompiled after applying that commit. Also,
	 * I don't want to search /proc/kallsyms for d_absolute_path() because
	 * I want to keep TOMOYO 1.x architecture independent. Thus, supply
	 * non empty root like AppArmor's d_namespace_path() did.
	 */
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		static bool kpr_no_empty;
		if (!kpr_no_empty) {
			struct path root = { };
			pos = ccsecurity_exports.__d_path(path, &root, buffer,
							  buflen - 1);
		} else {
			pos = NULL;
		}
		if (!pos) {
			struct task_struct *task = current;
			struct path root;
			struct path tmp;
			spin_lock(&task->fs->lock);
			root.mnt = task->nsproxy->mnt_ns->root;
			root.dentry = root.mnt->mnt_root;
			path_get(&root);
			spin_unlock(&task->fs->lock);
			tmp = root;
			pos = ccsecurity_exports.__d_path(path, &tmp, buffer,
							  buflen - 1);
			path_put(&root);
			if (!pos)
				return ERR_PTR(-EINVAL);
			/* Remember if __d_path() needs non empty root. */
			kpr_no_empty = true;
		}
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = path->dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#else
	char *pos = buffer + buflen - 1;
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	const char *name;
	int len;

	if (buflen < 256)
		goto out;

	*pos = '\0';
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		*--pos = '/';
	for (;;) {
		struct dentry *parent;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		name = dentry->d_name.name;
		len = dentry->d_name.len;
		pos -= len;
		if (pos <= buffer)
			goto out;
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	if (*pos == '/')
		pos++;
	len = dentry->d_name.len;
	pos -= len;
	if (pos < buffer)
		goto out;
	memmove(pos, dentry->d_name.name, len);
	return pos;
out:
	return ERR_PTR(-ENOMEM);
#endif
}

/**
 * kpr_encode - Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *kpr_encode(const char *str)
{
	int i;
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;
	const int str_len = strlen(str);
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];
		if (c == '\\')
			len += 2;
		else if (c > ' ' && c < 127)
			len++;
		else
			len += 4;
	}
	len++;
	cp = kzalloc(len, GFP_KERNEL);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];
		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * kpr_realpath - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *kpr_realpath(struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	while (1) {
		char *pos;
		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf)
			break;
		/* To make sure that pos is '\0' terminated. */
		buf[buf_len - 1] = '\0';
		kpr_realpath_lock();
		pos = kpr_get_absolute_path(path, buf, buf_len - 1);
		kpr_realpath_unlock();
		if (IS_ERR(pos))
			continue;
		name = kpr_encode(pos);
		break;
	}
	kfree(buf);
	return name;
}

/**
 * kpr_get_exe - Get kpr_realpath() of current process.
 *
 * Returns the kpr_realpath() of current process on success, NULL otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function didn't return NULL.
 */
static const char *kpr_get_exe(void)
{
	struct mm_struct *mm = current->mm;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct vm_area_struct *vma;
#endif
	const char *cp = NULL;
	if (!mm)
		return kstrdup("<kernel>", GFP_KERNEL);
	down_read(&mm->mmap_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	if (mm->exe_file)
		cp = kpr_realpath(&mm->exe_file->f_path);
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
			struct path path = { vma->vm_file->f_vfsmnt,
					     vma->vm_file->f_dentry };
			cp = kpr_realpath(&path);
#else
			cp = kpr_realpath(&vma->vm_file->f_path);
#endif
			break;
		}
	}
#endif
	up_read(&mm->mmap_sem);
	return cp;
}

/**
 * kpr_socket_bind_permission - Check permission for setting the local address of a socket.
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int kpr_socket_bind_permission(struct socket *sock,
				      struct sockaddr *addr, int addr_len)
{
	const char *exe;
	u16 port;
	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		break;
	default:
		return 0;
	}
	switch (sock->type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			return 0;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			return 0;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		return 0;
	}
	port = ntohs(port);
	if (!test_bit(port, reserved_port_map))
		return 0;
	exe = kpr_get_exe();
	if (!exe) {
		printk(KERN_WARNING "Unable to read /proc/self/exe . "
		       "Rejecting bind(%u) request.\n", port);
		return -ENOMEM;
	} else {
		struct reserved_port_entry *ptr;
		int ret = 0;
		rcu_read_lock();
		list_for_each_entry_rcu(ptr, &reserved_port_list, list) {
			if (port != ptr->port)
				continue;
			if (strcmp(exe, ptr->exe)) {
				ret = -EADDRINUSE;
				continue;
			}
			ret = 0;
			break;
		}
		rcu_read_unlock();
		kfree(exe);
		return ret;
	}
}

/**
 * kpr_socket_bind - Check permission for bind().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int kpr_socket_bind(struct socket *sock, struct sockaddr *addr,
			   int addr_len)
{
	const int rc = kpr_socket_bind_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	while (!original_security_ops.socket_bind);
	return original_security_ops.socket_bind(sock, addr, addr_len);
}

/**
 * kpr_read - read() for /proc/reserved_local_port interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Offset of @file.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t kpr_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	ssize_t copied = 0;
	int error = 0;
	int record = 0;
	loff_t offset = 0;
	char *data = vmalloc(MAX_LINE_LEN);
	if (!data)
		return -ENOMEM;
	while (1) {
		struct reserved_port_entry *ptr;
		int i = 0;
		data[0] = '\0';
		rcu_read_lock();
		list_for_each_entry_rcu(ptr, &reserved_port_list, list) {
			if (i++ < record)
				continue;
			snprintf(data, MAX_LINE_LEN - 1, "%u %s\n", ptr->port,
				 ptr->exe);
			break;
		}
		rcu_read_unlock();
		if (!data[0])
			break;
		for (i = 0; data[i]; i++) {
			if (offset++ < *ppos)
				continue;
			if (put_user(data[i], buf)) {
				error = -EFAULT;
				break;
			}
			buf++;
			copied++;
			(*ppos)++;
		}
		record++;
	}
	vfree(data);
	return copied ? copied : error;
}

/**
 * kpr_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Returns nothing.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
static void kpr_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/**
 * kpr_find_entry - Find an existing entry.
 *
 * @port: Port number.
 * @exe:  Pathname. NULL for any.
 *
 * Returns pointer to existing entry if found, NULL otherwise.
 */
static struct reserved_port_entry *kpr_find_entry(const u16 port,
						  const char *exe)
{
	struct reserved_port_entry *ptr;
	bool found = false;
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &reserved_port_list, list) {
		if (port != ptr->port)
			continue;
		if (exe && strcmp(exe, ptr->exe))
			continue;
		found = true;
		break;
	}
	rcu_read_unlock();
	return found ? ptr : NULL;
}

/**
 * kpr_update_entry - Update the list of whitelist elements.
 *
 * @data: Line of data to parse.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds a mutex to protect from concurrent updates.
 */
static int kpr_update_entry(const char *data)
{
	struct reserved_port_entry *ptr;
	unsigned int port;
	if (sscanf(data, "add %u", &port) == 1 && port < 65536) {
		const char *cp = strchr(data + 4, ' ');
		if (!cp++ || strchr(cp, ' '))
			return -EINVAL;
		if (kpr_find_entry(port, cp))
			return 0;
		ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
		if (!ptr)
			return -ENOMEM;
		ptr->port = (u16) port;
		ptr->exe = kstrdup(cp, GFP_KERNEL);
		if (!ptr->exe) {
			kfree(ptr);
			return -ENOMEM;
		}
		list_add_tail_rcu(&ptr->list, &reserved_port_list);
		set_bit(ptr->port, reserved_port_map);
	} else if (sscanf(data, "del %u", &port) == 1 && port < 65536) {
		const char *cp = strchr(data + 4, ' ');
		if (!cp++ || strchr(cp, ' '))
			return -EINVAL;
		ptr = kpr_find_entry(port, cp);
		if (!ptr)
			return 0;
		list_del_rcu(&ptr->list);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 12)
		synchronize_rcu();
#else
		synchronize_kernel();
#endif
		kfree(ptr->exe);
		kfree(ptr);
		if (!kpr_find_entry(port, NULL))
			clear_bit(ptr->port, reserved_port_map);
	} else {
		return -EINVAL;
	}
	return 0;
}

/**
 * kpr_write - write() for /proc/reserved_local_port interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes parsed on success, negative value otherwise.
 */
static ssize_t kpr_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	char *data;
	ssize_t copied = 0;
	int error;
	if (!count)
		return 0;
	if (count > MAX_LINE_LEN - 1)
		count = MAX_LINE_LEN - 1;
	data = vmalloc(count + 1);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
	data[count] = '\0';
	while (1) {
		static DEFINE_MUTEX(lock);
		char *cp = strchr(data, '\n');
		int len;
		if (!cp) {
			error = -EINVAL;
			break;
		}
		*cp = '\0';
		len = strlen(data) + 1;
		kpr_normalize_line(data);
		if (mutex_lock_interruptible(&lock)) {
			error = -EINTR;
			break;
		}
		error = kpr_update_entry(data);
		mutex_unlock(&lock);
		if (error < 0)
			break;
		copied += len;
		memmove(data, data + len, strlen(data + len) + 1);
	}
out:
	vfree(data);
	return copied ? copied : error;
}

/* Operations for /proc/reserved_local_port interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations kpr_operations = {
	.write = kpr_write,
	.read  = kpr_read,
};

/**
 * kpr_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init kpr_init(void)
{
	struct proc_dir_entry *entry;
	struct security_operations *ops = probe_security_ops();
	if (!ops)
		goto out;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ccsecurity_exports.vfsmount_lock = probe_vfsmount_lock();
	if (!ccsecurity_exports.vfsmount_lock)
		goto out;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	ccsecurity_exports.__d_path = probe___d_path();
	if (!ccsecurity_exports.__d_path)
		goto out;
#else
	ccsecurity_exports.d_absolute_path = probe_d_absolute_path();
	if (!ccsecurity_exports.d_absolute_path)
		goto out;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	entry = proc_create("reserved_local_port", 0644, NULL,
			    &kpr_operations);
#else
	entry = create_proc_entry("reserved_local_port", 0644, NULL);
	if (entry)
		entry->proc_fops = &kpr_operations;
#endif
	if (!entry)
		goto out;
	original_security_ops.socket_bind = ops->socket_bind;
	smp_mb();
	ops->socket_bind = kpr_socket_bind;
	printk(KERN_INFO "kportreserve: 0.1   2013/08/02\n");
	return 0;
out:
	return -EINVAL;
}

module_init(kpr_init);
MODULE_LICENSE("GPL");
