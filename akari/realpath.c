/*
 * security/ccsecurity/realpath.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.1   2011/06/06
 */

#include "internal.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#define ccs_lookup_flags LOOKUP_FOLLOW
#else
#define ccs_lookup_flags (LOOKUP_FOLLOW | LOOKUP_POSITIVE)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define s_fs_info u.generic_sbp
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * SOCKET_I - Get "struct socket".
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns pointer to "struct socket".
 *
 * This is for compatibility with older kernels.
 */
static inline struct socket *SOCKET_I(struct inode *inode)
{
	return inode->i_sock ? &inode->u.socket_i : NULL;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)

/**
 * ccs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_lock(void)
{
	/* dcache_lock is locked by __d_path(). */
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * ccs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	/* dcache_lock is unlocked by __d_path(). */
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 36)

/**
 * ccs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * ccs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	spin_unlock(&dcache_lock);
}

#elif defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

/**
 * ccs_realpath_lock - Take locks for __d_path().
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
static inline void ccs_realpath_lock(void)
{
	spin_lock(ccsecurity_exports.vfsmount_lock);
	spin_lock(&dcache_lock);
}

/**
 * ccs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(ccsecurity_exports.vfsmount_lock);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)

/**
 * ccs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(ccsecurity_exports.vfsmount_lock);
}

/**
 * ccs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(ccsecurity_exports.vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#else

/**
 * ccs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
}

/**
 * ccs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
}

#endif

/**
 * ccs_kern_path - Wrapper for kern_path().
 *
 * @pathname: Pathname to resolve. Maybe NULL.
 * @flags:    Lookup flags.
 * @path:     Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_kern_path(const char *pathname, int flags, struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	if (!pathname || kern_path(pathname, flags, path))
		return -ENOENT;
#else
	struct nameidata nd;
	if (!pathname || path_lookup(pathname, flags, &nd))
		return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	*path = nd.path;
#else
	path->dentry = nd.dentry;
	path->mnt = nd.mnt;
#endif
#endif
	return 0;
}

/**
 * ccs_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
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
static char *ccs_get_absolute_path(struct path *path, char * const buffer,
				   const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		struct path root = { };
		pos = ccsecurity_exports.__d_path(path, &root, buffer,
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
 * ccs_get_dentry_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Based on dentry_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 */
static char *ccs_get_dentry_path(struct dentry *dentry, char * const buffer,
				 const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		/* rename_lock is locked/unlocked by dentry_path_raw(). */
		pos = dentry_path_raw(dentry, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#else
	char *pos = buffer + buflen - 1;
	if (buflen < 256)
		return ERR_PTR(-ENOMEM);
	*pos = '\0';
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		*--pos = '/';
	spin_lock(&dcache_lock);
	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;
		const char *name = dentry->d_name.name;
		const int len = dentry->d_name.len;
		pos -= len;
		if (pos <= buffer) {
			pos = ERR_PTR(-ENOMEM);
			break;
		}
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	spin_unlock(&dcache_lock);
	return pos;
#endif
}

/**
 * ccs_get_local_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
static char *ccs_get_local_path(struct dentry *dentry, char * const buffer,
				const int buflen)
{
	struct super_block *sb = dentry->d_sb;
	char *pos = ccs_get_dentry_path(dentry, buffer, buflen);
	if (IS_ERR(pos))
		return pos;
	/* Convert from $PID to self if $PID is current thread. */
	if (sb->s_magic == PROC_SUPER_MAGIC && *pos == '/') {
		char *ep;
		const pid_t pid = (pid_t) simple_strtoul(pos + 1, &ep, 10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (*ep == '/' && pid && pid ==
		    task_tgid_nr_ns(current, sb->s_fs_info)) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#else
		if (*ep == '/' && pid == ccs_sys_getpid()) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#endif
		goto prepend_filesystem_name;
	}
	/* Use filesystem name for unnamed devices. */
	if (!MAJOR(sb->s_dev))
		goto prepend_filesystem_name;
	{
		struct inode *inode = sb->s_root->d_inode;
		/*
		 * Use filesystem name if filesystems does not support rename()
		 * operation.
		 */
		if (inode->i_op && !inode->i_op->rename)
			goto prepend_filesystem_name;
	}
	/* Prepend device name. */
	{
		char name[64];
		int name_len;
		const dev_t dev = sb->s_dev;
		name[sizeof(name) - 1] = '\0';
		snprintf(name, sizeof(name) - 1, "dev(%u,%u):", MAJOR(dev),
			 MINOR(dev));
		name_len = strlen(name);
		pos -= name_len;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		return pos;
	}
	/* Prepend filesystem name. */
prepend_filesystem_name:
	{
		const char *name = sb->s_type->name;
		const int name_len = strlen(name);
		pos -= name_len + 1;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		pos[name_len] = ':';
	}
	return pos;
out:
	return ERR_PTR(-ENOMEM);
}

/**
 * ccs_get_socket_name - Get the name of a socket.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer.
 */
static char *ccs_get_socket_name(struct path *path, char * const buffer,
				 const int buflen)
{
	struct inode *inode = path->dentry->d_inode;
	struct socket *sock = inode ? SOCKET_I(inode) : NULL;
	struct sock *sk = sock ? sock->sk : NULL;
	if (sk) {
		snprintf(buffer, buflen, "socket:[family=%u:type=%u:"
			 "protocol=%u]", sk->sk_family, sk->sk_type,
			 sk->sk_protocol);
	} else {
		snprintf(buffer, buflen, "socket:[unknown]");
	}
	return buffer;
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * ccs_realpath_from_path - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_realpath_from_path(struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	struct dentry *dentry = path->dentry;
	struct super_block *sb;
	if (!dentry)
		return NULL;
	sb = dentry->d_sb;
	while (1) {
		char *pos;
		struct inode *inode;
		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, CCS_GFP_FLAGS);
		if (!buf)
			break;
		/* To make sure that pos is '\0' terminated. */
		buf[buf_len - 1] = '\0';
		/* Get better name for socket. */
		if (sb->s_magic == SOCKFS_MAGIC) {
			pos = ccs_get_socket_name(path, buf, buf_len - 1);
			goto encode;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		/* For "pipe:[\$]". */
		if (dentry->d_op && dentry->d_op->d_dname) {
			pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
			goto encode;
		}
#endif
		inode = sb->s_root->d_inode;
		/*
		 * Get local name for filesystems without rename() operation
		 * or dentry without vfsmount.
		 */
		if (!path->mnt || (inode->i_op && !inode->i_op->rename)) {
			pos = ccs_get_local_path(path->dentry, buf,
						 buf_len - 1);
			goto encode;
		}
		/* Get absolute name for the rest. */
		ccs_realpath_lock();
		pos = ccs_get_absolute_path(path, buf, buf_len - 1);
		ccs_realpath_unlock();
encode:
		if (IS_ERR(pos))
			continue;
		name = ccs_encode(pos);
		break;
	}
	kfree(buf);
	if (!name)
		ccs_warn_oom(__func__);
	return name;
}

/**
 * ccs_symlink_path - Get symlink's pathname.
 *
 * @pathname: The pathname to solve.
 * @name:     Pointer to "struct ccs_path_info".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
int ccs_symlink_path(const char *pathname, struct ccs_path_info *name)
{
	char *buf;
	struct path path;
	if (ccs_kern_path(pathname, ccs_lookup_flags ^ LOOKUP_FOLLOW, &path))
		return -ENOENT;
	buf = ccs_realpath_from_path(&path);
	path_put(&path);
	if (buf) {
		name->name = buf;
		ccs_fill_path_info(name);
		return 0;
	}
	return -ENOMEM;
}

/**
 * ccs_encode2 - Encode binary string to ascii string.
 *
 * @str:     String in binary format.
 * @str_len: Size of @str in byte.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_encode2(const char *str, int str_len)
{
	int i;
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;
	if (!p)
		return NULL;
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
	/* Reserve space for appending "/". */
	cp = kzalloc(len + 10, CCS_GFP_FLAGS);
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
 * ccs_encode - Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_encode(const char *str)
{
	return str ? ccs_encode2(str, strlen(str)) : NULL;
}

/**
 * ccs_get_path - Get dentry/vfsmmount of a pathname.
 *
 * @pathname: The pathname to solve.
 * @path:     Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_get_path(const char *pathname, struct path *path)
{
	return ccs_kern_path(pathname, ccs_lookup_flags, path);
}
