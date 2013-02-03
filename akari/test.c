/*
 * akari_test.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 */
#include "probe.h"

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int __init ccs_init(void)
{
#ifdef CONFIG_SECURITY_COMPOSER_MAX
	if (!ccs_find_lsm_hooks_list())
		goto out;
#else
	if (!ccs_find_security_ops())
		goto out;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (!ccs_find_find_task_by_vpid())
		goto out;
	if (!ccs_find_find_task_by_pid_ns())
		goto out;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	if (!ccs_find_vfsmount_lock())
		goto out;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	if (!ccs_find___d_path())
		goto out;
#else
	if (!ccs_find_d_absolute_path())
		goto out;
#endif
	printk(KERN_INFO "All dependent symbols have been guessed.\n");
	printk(KERN_INFO "Please verify these addresses using System.map for "
	       "this kernel (e.g. /boot/System.map-`uname -r` ).\n");
	printk(KERN_INFO "If these addresses are correct, you can try loading "
	       "AKARI module on this kernel.\n");
	return 0;
out:
	printk(KERN_INFO "Sorry, I couldn't guess dependent symbols.\n");
	printk(KERN_INFO "I need some changes for supporting your "
	       "environment.\n");
	printk(KERN_INFO "Please contact the author.\n");
	return -EINVAL;
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
