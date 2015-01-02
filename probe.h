#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/security.h>
#ifndef __init
#include <linux/init.h>
#endif

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

#if defined(CONFIG_SECURITY_COMPOSER_MAX)
struct list_head;
struct list_head * __init probe_lsm_hooks_list(void);
#else
struct security_operations;
struct security_operations * __init probe_security_ops(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
void * __init probe_find_task_by_vpid(void);
void * __init probe_find_task_by_pid_ns(void);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
void * __init probe_vfsmount_lock(void);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
void * __init probe___d_path(void);
#else
void * __init probe_d_absolute_path(void);
#endif
