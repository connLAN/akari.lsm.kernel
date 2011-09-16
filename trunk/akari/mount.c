/*
 * security/ccsecurity/mount.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3-pre   2011/09/16
 */

#include "internal.h"

/* String table for special mount operations. */
static const char * const ccs_mounts[CCS_MAX_SPECIAL_MOUNT] = {
	[CCS_MOUNT_BIND]            = "--bind",
	[CCS_MOUNT_MOVE]            = "--move",
	[CCS_MOUNT_REMOUNT]         = "--remount",
	[CCS_MOUNT_MAKE_UNBINDABLE] = "--make-unbindable",
	[CCS_MOUNT_MAKE_PRIVATE]    = "--make-private",
	[CCS_MOUNT_MAKE_SLAVE]      = "--make-slave",
	[CCS_MOUNT_MAKE_SHARED]     = "--make-shared",
};

/**
 * ccs_audit_mount_log - Audit mount log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_mount_log(struct ccs_request_info *r)
{
	return ccs_supervisor(r, "file mount %s %s %s 0x%lX\n",
			      r->param.mount.dev->name,
			      r->param.mount.dir->name,
			      r->param.mount.type->name, r->param.mount.flags);
}

/**
 * ccs_check_mount_acl - Check permission for path path path number operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_mount_acl(struct ccs_request_info *r,
				const struct ccs_acl_info *ptr)
{
	const struct ccs_mount_acl *acl =
		container_of(ptr, typeof(*acl), head);
	return ccs_compare_number_union(r->param.mount.flags, &acl->flags) &&
		ccs_compare_name_union(r->param.mount.type, &acl->fs_type) &&
		ccs_compare_name_union(r->param.mount.dir, &acl->dir_name) &&
		(!r->param.mount.need_dev ||
		 ccs_compare_name_union(r->param.mount.dev, &acl->dev_name));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * module_put - Put a reference on module.
 *
 * @module: Pointer to "struct module". Maybe NULL.
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void module_put(struct module *module)
{
	if (module)
		__MOD_DEC_USE_COUNT(module);
}

#endif

/**
 * ccs_put_filesystem - Wrapper for put_filesystem().
 *
 * @fstype: Pointer to "struct file_system_type".
 *
 * Returns nothing.
 *
 * Since put_filesystem() is not exported, I embed put_filesystem() here.
 */
static inline void ccs_put_filesystem(struct file_system_type *fstype)
{
	module_put(fstype->owner);
}

/**
 * ccs_mount_acl - Check permission for mount() operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file. Maybe NULL.
 * @dir:      Pointer to "struct path".
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_mount_acl(struct ccs_request_info *r, char *dev_name,
			 struct path *dir, const char *type,
			 unsigned long flags)
{
	struct ccs_obj_info obj = { };
	struct file_system_type *fstype = NULL;
	const char *requested_type = NULL;
	const char *requested_dir_name = NULL;
	const char *requested_dev_name = NULL;
	struct ccs_path_info rtype;
	struct ccs_path_info rdev;
	struct ccs_path_info rdir;
	int need_dev = 0;
	int error = -ENOMEM;
	r->obj = &obj;

	/* Get fstype. */
	requested_type = ccs_encode(type);
	if (!requested_type)
		goto out;
	rtype.name = requested_type;
	ccs_fill_path_info(&rtype);

	/* Get mount point. */
	obj.path2 = *dir;
	requested_dir_name = ccs_realpath_from_path(dir);
	if (!requested_dir_name) {
		error = -ENOMEM;
		goto out;
	}
	rdir.name = requested_dir_name;
	ccs_fill_path_info(&rdir);

	/* Compare fs name. */
	if (type == ccs_mounts[CCS_MOUNT_REMOUNT]) {
		/* dev_name is ignored. */
	} else if (type == ccs_mounts[CCS_MOUNT_MAKE_UNBINDABLE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_PRIVATE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_SLAVE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_SHARED]) {
		/* dev_name is ignored. */
	} else if (type == ccs_mounts[CCS_MOUNT_BIND] ||
		   type == ccs_mounts[CCS_MOUNT_MOVE]) {
		need_dev = -1; /* dev_name is a directory */
	} else {
		fstype = get_fs_type(type);
		if (!fstype) {
			error = -ENODEV;
			goto out;
		}
		if (fstype->fs_flags & FS_REQUIRES_DEV)
			/* dev_name is a block device file. */
			need_dev = 1;
	}
	if (need_dev) {
		/* Get mount point or device file. */
		if (ccs_get_path(dev_name, &obj.path1)) {
			error = -ENOENT;
			goto out;
		}
		requested_dev_name = ccs_realpath_from_path(&obj.path1);
		if (!requested_dev_name) {
			error = -ENOENT;
			goto out;
		}
	} else {
		/* Map dev_name to "<NULL>" if no dev_name given. */
		if (!dev_name)
			dev_name = "<NULL>";
		requested_dev_name = ccs_encode(dev_name);
		if (!requested_dev_name) {
			error = -ENOMEM;
			goto out;
		}
	}
	rdev.name = requested_dev_name;
	ccs_fill_path_info(&rdev);
	r->param_type = CCS_TYPE_MOUNT_ACL;
	r->param.mount.need_dev = need_dev;
	r->param.mount.dev = &rdev;
	r->param.mount.dir = &rdir;
	r->param.mount.type = &rtype;
	r->param.mount.flags = flags;
	do {
		ccs_check_acl(r, ccs_check_mount_acl);
		error = ccs_audit_mount_log(r);
	} while (error == CCS_RETRY_REQUEST);
out:
	kfree(requested_dev_name);
	kfree(requested_dir_name);
	if (fstype)
		ccs_put_filesystem(fstype);
	kfree(requested_type);
	/* Drop refcount obtained by ccs_get_path(). */
	if (obj.path1.dentry)
		path_put(&obj.path1);
	return error;
}

/**
 * __ccs_mount_permission - Check permission for mount() operation.
 *
 * @dev_name:  Name of device file. Maybe NULL.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mount_permission(char *dev_name, struct path *path,
				  const char *type, unsigned long flags,
				  void *data_page)
{
	struct ccs_request_info r;
	int error = 0;
	int idx;
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	if (flags & MS_REMOUNT) {
		type = ccs_mounts[CCS_MOUNT_REMOUNT];
		flags &= ~MS_REMOUNT;
	}
	if (flags & MS_MOVE) {
		type = ccs_mounts[CCS_MOUNT_MOVE];
		flags &= ~MS_MOVE;
	}
	if (flags & MS_BIND) {
		type = ccs_mounts[CCS_MOUNT_BIND];
		flags &= ~MS_BIND;
	}
	if (flags & MS_UNBINDABLE) {
		type = ccs_mounts[CCS_MOUNT_MAKE_UNBINDABLE];
		flags &= ~MS_UNBINDABLE;
	}
	if (flags & MS_PRIVATE) {
		type = ccs_mounts[CCS_MOUNT_MAKE_PRIVATE];
		flags &= ~MS_PRIVATE;
	}
	if (flags & MS_SLAVE) {
		type = ccs_mounts[CCS_MOUNT_MAKE_SLAVE];
		flags &= ~MS_SLAVE;
	}
	if (flags & MS_SHARED) {
		type = ccs_mounts[CCS_MOUNT_MAKE_SHARED];
		flags &= ~MS_SHARED;
	}
	if (!type)
		type = "<NULL>";
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, CCS_MAC_FILE_MOUNT)
	    != CCS_CONFIG_DISABLED)
		error = ccs_mount_acl(&r, dev_name, path, type, flags);
	ccs_read_unlock(idx);
	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_old_mount_permission - Check permission for mount() operation.
 *
 * @dev_name:  Name of device file.
 * @nd:        Pointer to "struct nameidata".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_old_mount_permission(char *dev_name, struct nameidata *nd,
				    const char *type, unsigned long flags,
				    void *data_page)
{
	struct path path = { nd->mnt, nd->dentry };
	return __ccs_mount_permission(dev_name, &path, type, flags, data_page);
}

#endif

/**
 * ccs_mount_init - Register hooks for mount() operation.
 *
 * Returns nothing.
 *
 * Since checking permission for mount() operation is complicated compared to
 * other file related operations, I split code for mount() operation.
 */
void __init ccs_mount_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ccsecurity_ops.mount_permission = __ccs_mount_permission;
#else
	ccsecurity_ops.mount_permission = ccs_old_mount_permission;
#endif
}
