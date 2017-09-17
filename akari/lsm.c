/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.37   2017/09/17
 */

#include <linux/version.h>
#include <linux/security.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include "lsm-4.12.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#include "lsm-4.7.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include "lsm-4.2.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#include "lsm-2.6.29.c"
/*
 * AppArmor patch added "struct vfsmount *" to security_inode_\*() hooks.
 * Detect it by checking whether D_PATH_DISCONNECT is defined or not.
 * Also, there may be other kernels with "struct vfsmount *" added.
 * If you got build failure, check security_inode_\*() hooks in
 * include/linux/security.h.
 */
#elif defined(D_PATH_DISCONNECT) 
#include "lsm-2.6.0-vfs.c"
#elif defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 25)
#include "lsm-2.6.0-vfs.c"
#elif defined(CONFIG_SECURITY_APPARMOR) && LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 24)
#include "lsm-2.6.0-vfs.c"
#else
#include "lsm-2.6.0.c"
#endif
